package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"cspm-dashboard/backend/models"
)

// CloudTrailScanner checks CloudTrail configuration for audit-logging
// misconfigurations. It implements the Scanner interface.
//
// CloudTrail is AWS's primary audit log service — it records every API call
// made in the account. Misconfiguring it is uniquely dangerous because an
// attacker who achieves access will often attempt to cover their tracks by
// disabling or tampering with logs. These checks ensure the logging
// infrastructure itself is correctly hardened.
type CloudTrailScanner struct {
	client    *cloudtrail.Client
	s3Client  *s3.Client
	accountID string
	region    string
}

// NewCloudTrailScanner creates a CloudTrailScanner from an already-configured
// AWS SDK config.
func NewCloudTrailScanner(cfg aws.Config, accountID string) *CloudTrailScanner {
	return &CloudTrailScanner{
		client:    cloudtrail.NewFromConfig(cfg),
		s3Client:  s3.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *CloudTrailScanner) ServiceName() string { return "CloudTrail" }

// Scan fetches all trails in the region and runs every check against them.
//
// Unlike EC2 or S3, DescribeTrails does not paginate — AWS limits accounts to
// five trails per region, so one API call returns everything. However, checking
// whether a trail is actively logging requires a separate GetTrailStatus call
// per trail, so the total API calls scale with the number of trails found.
//
// If no trails exist at all, a single account-level finding is returned and
// the per-trail checks are skipped (there is nothing to inspect).
func (s *CloudTrailScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// IncludeShadowTrails: false — return only trails whose home region is the
	// region we are currently scanning. Shadow trails are read-only projections
	// of multi-region trails homed elsewhere; we do not want to re-report their
	// misconfigurations in every region they cover.
	out, err := s.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("cloudtrail: describing trails: %w", err)
	}

	trails := out.TrailList

	// If there are no trails at all, emit one account-level finding and stop.
	// There is nothing further to inspect when the service is not configured.
	if len(trails) == 0 {
		findings = append(findings, s.noTrailsFinding())
		return findings, nil
	}

	// Run all per-trail checks. Errors from GetTrailStatus on individual trails
	// are skipped so one inaccessible trail does not abort the rest.
	for _, trail := range trails {
		if f := s.checkTrailLogging(ctx, trail); f != nil {
			findings = append(findings, *f)
		}
		if f := s.checkLogFileValidation(trail); f != nil {
			findings = append(findings, *f)
		}
		if f := s.checkMultiRegion(trail); f != nil {
			findings = append(findings, *f)
		}
		if f := s.checkKMSEncryption(trail); f != nil {
			findings = append(findings, *f)
		}
		if f := s.checkS3BucketLogging(ctx, trail); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// noTrailsFinding returns an account-level finding used when no CloudTrail
// trails exist in the region at all. Because there is no specific trail
// resource to reference, the ResourceID uses a wildcard ARN pattern to
// indicate the entire service in this region is unconfigured.
func (s *CloudTrailScanner) noTrailsFinding() models.Finding {
	return models.Finding{
		ID:           generateID(),
		ResourceID:   fmt.Sprintf("arn:aws:cloudtrail:%s:%s:trail/*", s.region, s.accountID),
		ResourceType: "AWS::CloudTrail::Trail",
		ResourceName: s.region,
		Service:      s.ServiceName(),
		Severity:     models.SeverityCritical,
		Title:        "CloudTrail is not enabled in this region",
		Description: fmt.Sprintf(
			"No CloudTrail trails are configured in region %s. Every API call made "+
				"in this region — including calls that create, modify, or delete resources "+
				"— is unrecorded. Without audit logs, there is no way to detect an "+
				"intrusion, investigate a security incident, or satisfy compliance "+
				"requirements that mandate activity logging.",
			s.region),
		Recommendation: "Create a CloudTrail trail in this region, or preferably create " +
			"a single multi-region trail that covers all regions automatically. Enable " +
			"log file validation and KMS encryption at creation time to satisfy CIS " +
			"controls 3.2 and 3.7 simultaneously.",
		CISControl:           "3.1",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST", "HIPAA"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// checkTrailLogging detects whether a trail exists but has logging turned off.
//
// Why it matters (CIS 3.1):
// A trail that is not logging is a misconfiguration that is easy to overlook —
// the trail resource exists in the console, which can create a false sense of
// security, but no events are being recorded. This can happen accidentally
// (logging was temporarily disabled for maintenance and never re-enabled) or
// maliciously (an attacker with sufficient privileges disables logging to hide
// their activity before taking destructive action).
//
// GetTrailStatus is a separate API call from DescribeTrails because trail
// configuration (what to log) and trail status (is it currently logging) are
// stored and served independently by the CloudTrail API.
func (s *CloudTrailScanner) checkTrailLogging(ctx context.Context, trail types.Trail) *models.Finding {
	status, err := s.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
		Name: trail.TrailARN,
	})
	if err != nil {
		// Cannot determine logging status — skip rather than false-positive.
		return nil
	}

	if aws.ToBool(status.IsLogging) {
		return nil
	}

	name := aws.ToString(trail.Name)
	return s.newFinding(trail,
		models.SeverityCritical,
		"CloudTrail trail is not currently logging",
		fmt.Sprintf(
			"Trail '%s' exists but logging is disabled. API calls in this region "+
				"are not being recorded. An attacker with the cloudtrail:StopLogging "+
				"permission can exploit this to operate without leaving audit evidence.",
			name),
		fmt.Sprintf(
			"Re-enable logging on trail '%s' immediately using the AWS console or "+
				"by calling cloudtrail:StartLogging. Investigate why logging was stopped "+
				"— if it was not intentional, treat it as a potential security incident. "+
				"Consider adding a CloudWatch alarm on CloudTrail API calls "+
				"(StopLogging, DeleteTrail) to alert on future tampering.",
			name),
		"3.1",
	)
}

// checkLogFileValidation detects whether a trail has log file integrity
// validation disabled.
//
// Why it matters (CIS 3.2):
// CloudTrail delivers log files to an S3 bucket. Without validation, there is
// no cryptographic way to detect whether log files were modified or deleted
// after delivery. An attacker who gains write access to the S3 bucket could
// alter or delete log files to erase evidence of their activity, and the
// tampering would be undetectable.
//
// When validation is enabled, CloudTrail generates a signed digest file every
// hour that contains the SHA-256 hash of every log file delivered in that
// period. The digest is signed with a KMS-protected key. Verifying the digest
// chain proves that log files are complete and unmodified.
func (s *CloudTrailScanner) checkLogFileValidation(trail types.Trail) *models.Finding {
	if aws.ToBool(trail.LogFileValidationEnabled) {
		return nil
	}

	name := aws.ToString(trail.Name)
	return s.newFinding(trail,
		models.SeverityHigh,
		"CloudTrail log file integrity validation is not enabled",
		fmt.Sprintf(
			"Trail '%s' does not have log file integrity validation enabled. "+
				"CloudTrail delivers log files to S3, but without validation there is "+
				"no way to detect whether those files were tampered with or deleted "+
				"after delivery. An attacker with S3 write access could modify logs "+
				"to conceal malicious activity.",
			name),
		fmt.Sprintf(
			"Enable log file validation on trail '%s'. This can be done in the "+
				"CloudTrail console under trail settings, or via the AWS CLI: "+
				"'aws cloudtrail update-trail --name %s --enable-log-file-validation'. "+
				"After enabling, use 'aws cloudtrail validate-logs' periodically or "+
				"in a compliance pipeline to verify log integrity.",
			name, name),
		"3.2",
	)
}

// checkMultiRegion detects whether a trail is configured as a single-region
// trail rather than covering all AWS regions.
//
// Why it matters (CIS 3.1):
// AWS accounts operate across many regions simultaneously. A single-region
// trail only records API calls made in the trail's home region. An attacker
// who knows which regions are unmonitored can create resources, exfiltrate
// data, or establish persistence in those blind-spot regions with no audit
// trail. Modern AWS accounts routinely see API activity in regions they never
// intentionally use — from misconfigured tools, compromised credentials testing
// access, or services that call cross-region APIs.
//
// A multi-region trail records API calls from all regions into a single S3
// bucket and incurs no additional cost beyond the storage of the extra logs.
func (s *CloudTrailScanner) checkMultiRegion(trail types.Trail) *models.Finding {
	if aws.ToBool(trail.IsMultiRegionTrail) {
		return nil
	}

	name := aws.ToString(trail.Name)
	return s.newFinding(trail,
		models.SeverityMedium,
		"CloudTrail trail is not configured as a multi-region trail",
		fmt.Sprintf(
			"Trail '%s' only records API calls in region %s. All other AWS regions "+
				"in this account are unmonitored. An attacker can operate in any "+
				"unmonitored region without generating any audit log entries.",
			name, s.region),
		fmt.Sprintf(
			"Convert trail '%s' to a multi-region trail: in the console, edit the "+
				"trail and enable 'Apply trail to all regions', or via the AWS CLI: "+
				"'aws cloudtrail update-trail --name %s --is-multi-region-trail'. "+
				"The trail's S3 bucket will then receive logs from all regions "+
				"organised under region-specific prefixes.",
			name, name),
		"3.1",
	)
}

// checkKMSEncryption detects whether a trail's log files are encrypted with
// a customer-managed KMS key.
//
// Why it matters (CIS 3.7):
// By default, CloudTrail log files are encrypted at rest using SSE-S3
// (AES-256), which provides encryption but delegates all key management to
// AWS. With SSE-S3, anyone with s3:GetObject permission on the log bucket can
// read log files without any additional key-access check.
//
// When a KMS key is configured, CloudTrail additionally encrypts each log file
// with the specified key. Reading a log file then requires both s3:GetObject
// AND kms:Decrypt permission for that specific key. This creates a second
// access control layer around audit logs — the most sensitive data in an
// account — and produces a KMS key usage audit trail (via CloudTrail itself,
// which is pleasingly self-referential). Separation of duties between S3
// admins and KMS key admins is then achievable.
func (s *CloudTrailScanner) checkKMSEncryption(trail types.Trail) *models.Finding {
	if aws.ToString(trail.KmsKeyId) != "" {
		return nil
	}

	name := aws.ToString(trail.Name)
	return s.newFinding(trail,
		models.SeverityMedium,
		"CloudTrail log files are not encrypted with a KMS key",
		fmt.Sprintf(
			"Trail '%s' does not use a KMS customer-managed key to encrypt log "+
				"files. Logs are protected only by SSE-S3, which means any principal "+
				"with s3:GetObject on the log bucket can read audit logs without "+
				"any additional access check. This makes it harder to restrict who "+
				"can read sensitive audit data.",
			name),
		fmt.Sprintf(
			"Associate a KMS key with trail '%s': create a dedicated CMK for "+
				"CloudTrail logs, attach a key policy that allows CloudTrail to use "+
				"it (see AWS docs for the required policy statements), then update "+
				"the trail: 'aws cloudtrail update-trail --name %s --kms-key-id <key-arn>'. "+
				"Restrict kms:Decrypt on the key to only the roles that genuinely "+
				"need to read audit logs (e.g., security team, SIEM ingestion role).",
			name, name),
		"3.7",
	)
}

// checkS3BucketLogging detects whether the S3 bucket used to store CloudTrail
// logs has server access logging enabled on it.
//
// Why it matters (CloudTrail.7 / CIS 3.6):
// CloudTrail delivers audit logs to an S3 bucket. Without access logging on
// that bucket, there is no record of who accessed, downloaded, or deleted
// audit logs. An attacker who can read logs gains intelligence about defender
// monitoring; one who can delete them can cover their tracks. S3 access logs
// for the CloudTrail bucket create a second-order audit trail of log access itself.
func (s *CloudTrailScanner) checkS3BucketLogging(ctx context.Context, trail types.Trail) *models.Finding {
	bucket := aws.ToString(trail.S3BucketName)
	if bucket == "" {
		return nil
	}

	out, err := s.s3Client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		// Cannot check (e.g., bucket in another account) — skip.
		return nil
	}

	if out.LoggingEnabled != nil {
		return nil
	}

	return s.newFinding(trail,
		models.SeverityMedium,
		"S3 bucket for CloudTrail logs does not have server access logging enabled",
		fmt.Sprintf(
			"The S3 bucket '%s' storing CloudTrail logs for trail '%s' does not have "+
				"server access logging enabled. Without it, there is no record of who accessed "+
				"or deleted the audit logs themselves — an attacker could exfiltrate or tamper "+
				"with logs without leaving any trace.",
			bucket, aws.ToString(trail.Name)),
		fmt.Sprintf(
			"Enable server access logging on S3 bucket '%s'. Deliver logs to a separate "+
				"dedicated logging bucket (not the CloudTrail bucket itself) so that log "+
				"access records are stored independently. This satisfies CIS control 3.6.",
			bucket),
		"3.6",
	)
}

// newFinding is a convenience constructor that fills in the fields shared by
// every per-trail finding. The trail ARN is used directly as ResourceID since
// CloudTrail returns it from DescribeTrails — no manual ARN construction needed.
func (s *CloudTrailScanner) newFinding(
	trail types.Trail,
	severity models.Severity,
	title, description, recommendation, cisControl string,
) *models.Finding {
	return &models.Finding{
		ID:                   generateID(),
		ResourceID:           aws.ToString(trail.TrailARN),
		ResourceType:         "AWS::CloudTrail::Trail",
		ResourceName:         aws.ToString(trail.Name),
		Service:              s.ServiceName(),
		Severity:             severity,
		Title:                title,
		Description:          description,
		Recommendation:       recommendation,
		CISControl:           cisControl,
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST", "HIPAA"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}
