package scanners

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"cspm-dashboard/backend/models"
)

// EC2Scanner checks EC2 security groups and EBS volumes for common security
// misconfigurations. It implements the Scanner interface.
type EC2Scanner struct {
	client    *ec2.Client
	accountID string
	region    string
}

// NewEC2Scanner creates an EC2Scanner from an already-configured AWS SDK config.
func NewEC2Scanner(cfg aws.Config, accountID string) *EC2Scanner {
	return &EC2Scanner{
		client:    ec2.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *EC2Scanner) ServiceName() string { return "EC2" }

// Scan runs all EC2 security checks and returns every finding detected.
//
// Security group checks (CIS 5.2, 5.3, 5.4) are consolidated into one
// paginated pass over DescribeSecurityGroups so we only hit the API once
// regardless of how many per-group checks we add later. EBS encryption
// (CIS 2.2.1) is a separate paginated pass over DescribeVolumes.
func (s *EC2Scanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	sgFindings, err := s.checkSecurityGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("ec2: checking security groups: %w", err)
	}
	findings = append(findings, sgFindings...)

	ebsFindings, err := s.checkEBSEncryption(ctx)
	if err != nil {
		return nil, fmt.Errorf("ec2: checking EBS encryption: %w", err)
	}
	findings = append(findings, ebsFindings...)

	// CIS 3.9 — VPC flow logs must be enabled on every VPC.
	if vpcFindings, err := s.checkVPCFlowLogs(ctx); err == nil {
		findings = append(findings, vpcFindings...)
	}

	// EC2.7 — account-level EBS default encryption.
	if ebsDefaultFindings, err := s.checkEBSDefaultEncryption(ctx); err == nil {
		findings = append(findings, ebsDefaultFindings...)
	}

	// EC2.8 — IMDSv2 required on all instances.
	if imdsFindings, err := s.checkIMDSv2(ctx); err == nil {
		findings = append(findings, imdsFindings...)
	}

	// EC2.21 — NACLs must not allow unrestricted access to admin ports.
	if naclFindings, err := s.checkNACLAdminPorts(ctx); err == nil {
		findings = append(findings, naclFindings...)
	}

	return findings, nil
}

// checkSecurityGroups paginates over every security group in the region and
// runs three checks against each one: unrestricted SSH, unrestricted RDP, and
// default-SG-with-rules. Combining them into one loop avoids re-paginating for
// each check type.
func (s *EC2Scanner) checkSecurityGroups(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	paginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, sg := range page.SecurityGroups {
			// Checks 1 and 2 share the same logic; only the port and CIS control
			// differ. A single SG can produce both findings if it exposes both ports.
			if f := s.checkUnrestrictedPort(sg, 22, "SSH", "5.2"); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkUnrestrictedPort(sg, 3389, "RDP", "5.3"); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkDefaultSGTraffic(sg); f != nil {
				findings = append(findings, *f)
			}

			// Additional database and web port checks.
			for _, pc := range []struct {
				port int32
				name string
				cis  string
				sev  models.Severity
			}{
				{3306, "MySQL", "5.2", models.SeverityCritical},
				{5432, "PostgreSQL", "5.2", models.SeverityCritical},
				{27017, "MongoDB", "5.2", models.SeverityCritical},
				{1433, "MSSQL", "5.2", models.SeverityCritical},
				{80, "HTTP", "5.2", models.SeverityLow},
				{443, "HTTPS", "5.2", models.SeverityLow},
			} {
				if f := s.checkUnrestrictedPortSev(sg, pc.port, pc.name, pc.cis, pc.sev); f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}

	return findings, nil
}

// checkUnrestrictedPort returns a Finding if the security group has any inbound
// rule that allows traffic on the specified port from the IPv4 wildcard
// (0.0.0.0/0) or the IPv6 wildcard (::/0).
//
// Why unrestricted SSH matters (CIS 5.2):
// SSH is the primary remote-administration protocol for Linux instances. Exposing
// it to the entire internet makes the instance a target for brute-force and
// credential-stuffing attacks around the clock. Every publicly routable IP in the
// world can attempt to authenticate. Restrict SSH to known CIDR ranges (office
// egress IPs, a bastion host, or an AWS VPN endpoint) to eliminate this attack
// surface entirely.
//
// Why unrestricted RDP matters (CIS 5.3):
// RDP (port 3389) is the primary remote-administration protocol for Windows
// instances and has a long history of critical vulnerabilities (e.g., BlueKeep,
// DejaBlue). Publicly exposed RDP is one of the most common initial-access
// vectors in ransomware incidents. Apply the same restriction strategy as SSH.
func (s *EC2Scanner) checkUnrestrictedPort(sg types.SecurityGroup, port int32, portName, cisControl string) *models.Finding {
	for _, perm := range sg.IpPermissions {
		if !coversPort(perm, port) {
			continue
		}
		// The permission applies to our target port — now check if the source
		// is unrestricted. Both IPv4 and IPv6 wildcards are checked because
		// dual-stack instances are reachable via either.
		if !isUnrestricted(perm) {
			continue
		}

		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)
		vpcID := aws.ToString(sg.VpcId)

		return s.newFinding(
			fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", s.region, s.accountID, sgID),
			"AWS::EC2::SecurityGroup",
			sgName,
			models.SeverityCritical,
			fmt.Sprintf("Security group allows unrestricted inbound %s access (port %d)", portName, port),
			fmt.Sprintf(
				"Security group '%s' (%s) in VPC %s has an inbound rule that allows "+
					"port %d (%s) from 0.0.0.0/0 or ::/0. Any host on the internet can "+
					"attempt to connect to instances using this security group.",
				sgName, sgID, vpcID, port, portName),
			fmt.Sprintf(
				"Remove the wildcard inbound rule for port %d from security group '%s'. "+
					"Replace it with rules that allow access only from known, trusted CIDR "+
					"ranges such as a corporate VPN, a bastion host's private IP, or an AWS "+
					"Systems Manager Session Manager endpoint (which eliminates the need for "+
					"open %s ports entirely).",
				port, sgName, portName),
			cisControl,
		)
	}
	return nil
}

// checkDefaultSGTraffic returns a Finding if the security group is a VPC's
// default security group and it permits any inbound or outbound traffic.
//
// Why it matters (CIS 5.4):
// Every VPC comes with a default security group that is automatically assigned
// to any resource not explicitly given a different group. If the default SG
// has permissive rules, resources accidentally deployed without an explicit SG
// (a common misconfiguration in fast-moving teams) inherit those permissions
// silently. The safest posture is a default SG with zero rules: resources that
// land in it are effectively network-isolated and the misconfiguration is
// immediately visible rather than quietly exploitable.
//
// The default SG is identified by its group name ("default"), not by a flag
// field. Every VPC has exactly one, so this check fires once per VPC.
func (s *EC2Scanner) checkDefaultSGTraffic(sg types.SecurityGroup) *models.Finding {
	if aws.ToString(sg.GroupName) != "default" {
		return nil
	}

	// IpPermissions = inbound rules; IpPermissionsEgress = outbound rules.
	// Either being non-empty means traffic can flow through the default SG.
	hasInbound := len(sg.IpPermissions) > 0
	hasOutbound := len(sg.IpPermissionsEgress) > 0
	if !hasInbound && !hasOutbound {
		return nil
	}

	sgID := aws.ToString(sg.GroupId)
	vpcID := aws.ToString(sg.VpcId)

	// Describe which direction(s) have rules so the finding is actionable.
	direction := "inbound and outbound"
	if hasInbound && !hasOutbound {
		direction = "inbound"
	} else if !hasInbound && hasOutbound {
		direction = "outbound"
	}

	return s.newFinding(
		fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", s.region, s.accountID, sgID),
		"AWS::EC2::SecurityGroup",
		"default",
		models.SeverityMedium,
		"Default VPC security group allows traffic",
		fmt.Sprintf(
			"The default security group (%s) for VPC %s has %s rules. Resources "+
				"deployed without an explicit security group assignment are automatically "+
				"placed in the default SG, inheriting these permissions without the "+
				"deployer necessarily being aware of it.",
			sgID, vpcID, direction),
		fmt.Sprintf(
			"Remove all inbound and outbound rules from default security group %s. "+
				"AWS prevents deletion of the default SG, but it can be emptied. Ensure "+
				"all EC2 instances, RDS instances, and Lambda functions use explicitly "+
				"created security groups with documented, least-privilege rules.",
			sgID),
		"5.4",
	)
}

// checkEBSEncryption paginates over every EBS volume in the region and returns
// a Finding for each one that is not encrypted.
//
// Why it matters (CIS 2.2.1):
// EBS volumes persist to disk. An unencrypted volume is readable by anyone who
// can access the underlying storage — through a snapshot, a volume detached and
// reattached to another instance, or physical media access at the AWS level.
// Encryption at rest ensures that data is unreadable without access to the KMS
// key, even if the storage medium itself is compromised. AWS KMS encryption for
// EBS adds no performance overhead at the instance level (it is handled
// transparently by the hypervisor) and is free for AWS-managed keys.
//
// Note: enabling encryption on an existing unencrypted volume requires creating
// an encrypted snapshot and restoring from it — it cannot be done in-place.
// The account-level default encryption setting prevents new volumes from being
// created unencrypted and is the recommended permanent fix.
func (s *EC2Scanner) checkEBSEncryption(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	paginator := ec2.NewDescribeVolumesPaginator(s.client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, vol := range page.Volumes {
			// aws.ToBool safely dereferences the *bool field, treating nil as false.
			if aws.ToBool(vol.Encrypted) {
				continue
			}

			volID := aws.ToString(vol.VolumeId)
			// Derive a human-readable name from the Name tag if present;
			// fall back to the volume ID if no tag was set.
			volName := nameFromTags(vol.Tags, volID)

			findings = append(findings, *s.newFinding(
				fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", s.region, s.accountID, volID),
				"AWS::EC2::Volume",
				volName,
				models.SeverityHigh,
				"EBS volume is not encrypted",
				fmt.Sprintf(
					"EBS volume '%s' (%s) in region %s is not encrypted. Data written "+
						"to this volume is stored in plaintext. If the volume is snapshotted "+
						"and the snapshot is shared, or if the volume is detached and reused, "+
						"its contents are accessible without any additional authentication.",
					volName, volID, s.region),
				fmt.Sprintf(
					"To encrypt volume '%s': (1) create a snapshot of the volume, "+
						"(2) copy the snapshot with encryption enabled (specifying a KMS key), "+
						"(3) create a new volume from the encrypted snapshot, (4) swap the "+
						"volume on the instance. To prevent future unencrypted volumes, enable "+
						"'EBS encryption by default' in EC2 account settings for this region.",
					volName),
				"2.2.1",
			))
		}
	}

	return findings, nil
}

// newFinding fills in the fields that are the same for every EC2 finding.
func (s *EC2Scanner) newFinding(
	resourceID, resourceType, resourceName string,
	severity models.Severity,
	title, description, recommendation, cisControl string,
) *models.Finding {
	return &models.Finding{
		ID:                   generateID(),
		ResourceID:           resourceID,
		ResourceType:         resourceType,
		ResourceName:         resourceName,
		Service:              s.ServiceName(),
		Severity:             severity,
		Title:                title,
		Description:          description,
		Recommendation:       recommendation,
		CISControl:           cisControl,
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// =============================================================================
// Package-level helpers
// =============================================================================

// coversPort reports whether an IP permission applies to the given port number.
//
// The IpProtocol field uses "-1" to mean "all traffic" (every port, every
// protocol). For TCP/UDP rules, FromPort and ToPort define an inclusive range.
// Both fields are *int32; aws.ToInt32 dereferences them safely (nil → 0).
func coversPort(perm types.IpPermission, port int32) bool {
	if aws.ToString(perm.IpProtocol) == "-1" {
		return true // all-traffic rule covers every port
	}
	from := aws.ToInt32(perm.FromPort)
	to := aws.ToInt32(perm.ToPort)
	return from <= port && port <= to
}

// isUnrestricted reports whether an IP permission grants access from the
// IPv4 internet wildcard (0.0.0.0/0) or the IPv6 internet wildcard (::/0).
//
// Both must be checked: a dual-stack instance in a public subnet is reachable
// from either address family, so an IPv6-only wildcard rule is just as
// dangerous as an IPv4 one.
func isUnrestricted(perm types.IpPermission) bool {
	for _, r := range perm.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, r := range perm.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

// nameFromTags returns the value of the "Name" tag from an EC2 resource's tag
// list, or the fallback string if no Name tag is present. EC2 resources use
// tags for human-readable names rather than a dedicated name field.
func nameFromTags(tags []types.Tag, fallback string) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return fallback
}

// =============================================================================
// New checks — CIS 5.1, additional ports (5.2)
// =============================================================================

// checkUnrestrictedPortSev is identical to checkUnrestrictedPort but accepts
// a severity parameter, allowing database and web ports to carry different
// severity levels than SSH/RDP while reusing the same detection logic.
func (s *EC2Scanner) checkUnrestrictedPortSev(sg types.SecurityGroup, port int32, portName, cisControl string, severity models.Severity) *models.Finding {
	for _, perm := range sg.IpPermissions {
		if !coversPort(perm, port) {
			continue
		}
		if !isUnrestricted(perm) {
			continue
		}

		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)
		vpcID := aws.ToString(sg.VpcId)

		return s.newFinding(
			fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", s.region, s.accountID, sgID),
			"AWS::EC2::SecurityGroup",
			sgName,
			severity,
			fmt.Sprintf("Security group allows unrestricted inbound %s access (port %d)", portName, port),
			fmt.Sprintf(
				"Security group '%s' (%s) in VPC %s has an inbound rule that allows "+
					"port %d (%s) from 0.0.0.0/0 or ::/0. Any host on the internet can "+
					"attempt to connect to instances using this security group.",
				sgName, sgID, vpcID, port, portName),
			fmt.Sprintf(
				"Remove the wildcard inbound rule for port %d from security group '%s'. "+
					"Replace it with rules that allow access only from known, trusted CIDR "+
					"ranges. For database ports, access should never be permitted from the "+
					"public internet — place DB instances in private subnets instead.",
				port, sgName),
			cisControl,
		)
	}
	return nil
}

// checkVPCFlowLogs detects VPCs in the region that do not have VPC flow logs
// enabled.
//
// Why it matters (CIS 3.9):
// Flow logs record metadata about every IP packet that enters or leaves a
// network interface in the VPC: source/destination IP, port, protocol, bytes
// transferred, and whether the packet was accepted or rejected. Without them,
// there is no network-level visibility — you cannot detect port scans,
// lateral movement, data exfiltration over unusual ports, or verify that
// security groups are behaving as intended. Flow logs are the network
// equivalent of CloudTrail for the API plane.
func (s *EC2Scanner) checkVPCFlowLogs(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	vpcsOut, err := s.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}

	for _, vpc := range vpcsOut.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)

		flowOut, err := s.client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
			Filter: []types.Filter{
				{Name: aws.String("resource-id"), Values: []string{vpcID}},
			},
		})
		if err != nil {
			// Skip VPCs where we cannot check flow logs (e.g., permission denied).
			continue
		}

		hasActive := false
		for _, fl := range flowOut.FlowLogs {
			if aws.ToString(fl.FlowLogStatus) == "ACTIVE" {
				hasActive = true
				break
			}
		}

		if !hasActive {
			vpcName := nameFromTags(vpc.Tags, vpcID)
			findings = append(findings, *s.newFinding(
				fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", s.region, s.accountID, vpcID),
				"AWS::EC2::VPC",
				vpcName,
				models.SeverityHigh,
				"VPC does not have flow logs enabled",
				fmt.Sprintf(
					"VPC '%s' (%s) in region %s has no active flow logs. Without flow logs, "+
						"there is no record of network traffic — making it impossible to "+
						"investigate intrusions, detect data exfiltration, or verify that "+
						"security group rules are working as intended.",
					vpcName, vpcID, s.region),
				fmt.Sprintf(
					"Enable VPC flow logs for VPC '%s'. Deliver logs to CloudWatch Logs "+
						"for real-time alerting or to an S3 bucket for cost-effective storage. "+
						"Configure the log format to include all available fields including "+
						"vpc-id, subnet-id, instance-id, and tcp-flags.",
					vpcID),
				"3.9",
			))
		}
	}

	return findings, nil
}

// checkEBSDefaultEncryption detects whether account-level EBS encryption by
// default is disabled.
//
// Why it matters (EC2.7 / CIS 2.2.1):
// When EBS encryption by default is enabled, every new EBS volume created in
// the region is automatically encrypted — no per-volume setting required.
// Without it, developers who forget to check the encryption box create
// unencrypted volumes silently. Account-level default encryption is a safety net
// that eliminates human error from the equation entirely.
func (s *EC2Scanner) checkEBSDefaultEncryption(ctx context.Context) ([]models.Finding, error) {
	out, err := s.client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return nil, err
	}

	if aws.ToBool(out.EbsEncryptionByDefault) {
		return nil, nil
	}

	resourceID := fmt.Sprintf("arn:aws:ec2:%s:%s:account", s.region, s.accountID)
	return []models.Finding{*s.newFinding(
		resourceID,
		"AWS::EC2::Region",
		s.region,
		models.SeverityHigh,
		"EBS encryption by default is not enabled in this region",
		fmt.Sprintf(
			"Account-level EBS encryption by default is disabled in region %s. "+
				"Any new EBS volume created without an explicit encryption setting will "+
				"be stored in plaintext. This is a leading cause of unencrypted data at rest "+
				"and is trivially preventable with a single account setting.",
			s.region),
		fmt.Sprintf(
			"Enable EBS encryption by default in region %s: in the EC2 console under "+
				"'Account Attributes > EBS encryption', click 'Manage' and enable it. "+
				"Optionally specify a customer-managed KMS key for additional control. "+
				"This only affects new volumes — existing unencrypted volumes must be "+
				"migrated separately.",
			s.region),
		"2.2.1",
	)}, nil
}

// checkIMDSv2 paginates over every EC2 instance in the region and returns a
// finding for each one that does not require Instance Metadata Service v2.
//
// Why it matters (EC2.8):
// IMDSv2 requires a session-oriented request flow — the client must first
// obtain a session token before querying metadata. IMDSv1 (the default in
// older accounts) allows any process on the instance to query the metadata
// endpoint directly, including malicious code injected via SSRF. Requiring
// IMDSv2 eliminates SSRF as a path to credential theft from the metadata service.
func (s *EC2Scanner) checkIMDSv2(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				// Skip terminated instances — they are no longer running.
				if instance.State != nil && instance.State.Name == types.InstanceStateNameTerminated {
					continue
				}

				imdsRequired := instance.MetadataOptions != nil &&
					instance.MetadataOptions.HttpTokens == types.HttpTokensStateRequired

				if imdsRequired {
					continue
				}

				instanceID := aws.ToString(instance.InstanceId)
				instanceName := nameFromTags(instance.Tags, instanceID)

				findings = append(findings, *s.newFinding(
					fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", s.region, s.accountID, instanceID),
					"AWS::EC2::Instance",
					instanceName,
					models.SeverityHigh,
					"EC2 instance does not require IMDSv2",
					fmt.Sprintf(
						"Instance '%s' (%s) has HttpTokens set to 'optional', meaning IMDSv1 "+
							"is still accepted. Any process on the instance — including malicious "+
							"code introduced via SSRF or RCE — can query the metadata endpoint "+
							"without a session token and steal IAM role credentials.",
						instanceName, instanceID),
					fmt.Sprintf(
						"Require IMDSv2 on instance '%s': "+
							"'aws ec2 modify-instance-metadata-options --instance-id %s "+
							"--http-tokens required --http-endpoint enabled'. "+
							"Verify that applications running on the instance use IMDSv2 "+
							"(SDK v2 and IMDSv2-aware tools do this automatically).",
						instanceID, instanceID),
					"EC2.8",
				))
			}
		}
	}

	return findings, nil
}

// checkNACLAdminPorts detects Network ACL rules that allow unrestricted ingress
// to SSH (port 22) or RDP (port 3389) from 0.0.0.0/0 or ::/0.
//
// Why it matters (EC2.21):
// Unlike security groups (stateful), NACLs are stateless and apply at the subnet
// level. A permissive NACL ingress rule on an admin port allows traffic into the
// entire subnet before security groups can evaluate it. Removing these rules
// forces all SSH/RDP traffic through explicit security group rules on individual
// instances and eliminates subnet-wide exposure.
func (s *EC2Scanner) checkNACLAdminPorts(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	out, err := s.client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	for _, nacl := range out.NetworkAcls {
		naclID := aws.ToString(nacl.NetworkAclId)
		naclName := nameFromTags(nacl.Tags, naclID)

		for _, entry := range nacl.Entries {
			// Only inspect ingress (Egress == false) allow rules.
			if aws.ToBool(entry.Egress) {
				continue
			}
			if entry.RuleAction != types.RuleActionAllow {
				continue
			}

			// Check source CIDR.
			cidr := aws.ToString(entry.CidrBlock)
			ipv6Cidr := aws.ToString(entry.Ipv6CidrBlock)
			isUnrestrictedSrc := cidr == "0.0.0.0/0" || ipv6Cidr == "::/0"
			if !isUnrestrictedSrc {
				continue
			}

			// Determine whether the rule covers port 22 or 3389.
			protocol := aws.ToString(entry.Protocol)
			allTraffic := protocol == "-1"

			coversSSH := false
			coversRDP := false

			if allTraffic {
				coversSSH = true
				coversRDP = true
			} else if (protocol == "6" || protocol == "tcp") && entry.PortRange != nil {
				from := aws.ToInt32(entry.PortRange.From)
				to := aws.ToInt32(entry.PortRange.To)
				coversSSH = from <= 22 && 22 <= to
				coversRDP = from <= 3389 && 3389 <= to
			}

			if !coversSSH && !coversRDP {
				continue
			}

			var ports []string
			if coversSSH {
				ports = append(ports, "22 (SSH)")
			}
			if coversRDP {
				ports = append(ports, "3389 (RDP)")
			}
			portStr := strings.Join(ports, " and ")

			findings = append(findings, *s.newFinding(
				fmt.Sprintf("arn:aws:ec2:%s:%s:network-acl/%s", s.region, s.accountID, naclID),
				"AWS::EC2::NetworkAcl",
				naclName,
				models.SeverityHigh,
				fmt.Sprintf("Network ACL allows unrestricted ingress to %s", portStr),
				fmt.Sprintf(
					"Network ACL '%s' (%s) has an ALLOW rule permitting ingress from %s to "+
						"port(s) %s. NACLs apply at the subnet level before security groups, "+
						"so this rule exposes every instance in the associated subnets to "+
						"remote-administration attacks from the entire internet.",
					naclName, naclID, func() string {
						if cidr == "0.0.0.0/0" {
							return "0.0.0.0/0"
						}
						return "::/0"
					}(), portStr),
				fmt.Sprintf(
					"Remove or restrict the NACL ingress rule for port(s) %s in NACL '%s'. "+
						"Replace it with rules that allow SSH/RDP only from specific trusted "+
						"CIDR ranges (corporate VPN, bastion subnet). Consider using AWS Systems "+
						"Manager Session Manager to eliminate the need for open admin ports entirely.",
					portStr, naclID),
				"EC2.21",
			))
		}
	}

	return findings, nil
}
