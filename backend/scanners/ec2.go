package scanners

import (
	"context"
	"fmt"
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
