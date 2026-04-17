package scanners

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"cspm-dashboard/backend/models"
)

// S3Scanner checks every S3 bucket in the account for common security
// misconfigurations and returns a Finding for each one detected.
//
// It implements the Scanner interface, so the engine can run it alongside
// other service scanners without knowing anything about S3 specifically.
type S3Scanner struct {
	client    *s3.Client
	accountID string
	region    string
}

// NewS3Scanner creates an S3Scanner from an already-configured AWS SDK config.
// Build cfg once with config.LoadDefaultConfig (or equivalent) and pass it to
// every scanner so they all share the same credentials and region.
func NewS3Scanner(cfg aws.Config, accountID string) *S3Scanner {
	return &S3Scanner{
		client:    s3.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *S3Scanner) ServiceName() string { return "S3" }

// Scan lists every bucket in the account and runs all security checks against
// each one. It collects results from every bucket before returning, so a single
// inaccessible bucket never aborts the full scan — partial results are always
// better than no results in a CSPM context.
//
// A non-nil error is only returned for failures that prevent scanning entirely
// (e.g., no permission to call ListBuckets). Per-bucket errors are silently
// skipped so the scan stays resilient.
func (s *S3Scanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	listOut, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3: listing buckets: %w", err)
	}

	for _, bucket := range listOut.Buckets {
		name := aws.ToString(bucket.Name)

		// Run each check independently. If a check errors (e.g., access denied
		// on one specific bucket API call), we skip it rather than crashing the
		// whole scan. Production tools would log these skipped errors.
		if f, err := s.checkPublicAccessBlock(ctx, name); err == nil && f != nil {
			findings = append(findings, *f)
		}
		if f, err := s.checkEncryption(ctx, name); err == nil && f != nil {
			findings = append(findings, *f)
		}
		if f, err := s.checkLogging(ctx, name); err == nil && f != nil {
			findings = append(findings, *f)
		}
		if f, err := s.checkVersioning(ctx, name); err == nil && f != nil {
			findings = append(findings, *f)
		}
		if f, err := s.checkHTTPSPolicy(ctx, name); err == nil && f != nil {
			findings = append(findings, *f)
		}
		if f, err := s.checkPublicACL(ctx, name); err == nil && f != nil {
			findings = append(findings, *f)
		}
		if f, err := s.checkMFADelete(ctx, name); err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// checkPublicAccessBlock detects whether the bucket's S3 Block Public Access
// settings are fully enabled.
//
// Why it matters: S3 Block Public Access is a bucket-level safety net that
// overrides any ACL or bucket policy that would otherwise expose objects to the
// internet. AWS introduced it precisely because misconfigured ACLs and policies
// were a leading cause of S3 data breaches. All four settings must be true to
// provide complete coverage.
//
// CIS AWS Foundations Benchmark: 2.1.4
func (s *S3Scanner) checkPublicAccessBlock(ctx context.Context, bucket string) (*models.Finding, error) {
	out, err := s.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})

	// If the API returns an error it almost always means no Public Access Block
	// configuration exists at all — which is itself the misconfiguration.
	// (The specific sentinel error is types.NoSuchPublicAccessBlockConfiguration.)
	if err != nil {
		return s.newFinding(bucket,
			models.SeverityHigh,
			"S3 bucket does not have Block Public Access enabled",
			"The bucket has no S3 Block Public Access configuration. Without it, "+
				"a permissive bucket policy or ACL can expose objects to the internet.",
			"Enable all four Block Public Access settings on the bucket: "+
				"BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
			"2.1.4",
		), nil
	}

	cfg := out.PublicAccessBlockConfiguration
	// The SDK represents these as *bool pointers; aws.ToBool safely
	// dereferences them, returning false for a nil pointer.
	allEnabled := aws.ToBool(cfg.BlockPublicAcls) &&
		aws.ToBool(cfg.IgnorePublicAcls) &&
		aws.ToBool(cfg.BlockPublicPolicy) &&
		aws.ToBool(cfg.RestrictPublicBuckets)

	if !allEnabled {
		return s.newFinding(bucket,
			models.SeverityHigh,
			"S3 bucket Block Public Access settings are incomplete",
			"At least one of the four Block Public Access settings is disabled. "+
				"Partial configuration still leaves the bucket vulnerable to exposure via "+
				"ACLs or bucket policies.",
			"Enable all four Block Public Access settings: BlockPublicAcls, "+
				"IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
			"2.1.4",
		), nil
	}

	return nil, nil // bucket passes this check
}

// checkEncryption detects whether server-side encryption (SSE) is configured
// on the bucket.
//
// Why it matters: Without SSE, objects are stored in plaintext on disk. If AWS
// infrastructure were ever physically compromised, or if an attacker gained
// direct storage access, data would be exposed. SSE-S3 is the minimum bar;
// SSE-KMS is preferred because it provides an additional key management layer
// and an audit trail in CloudTrail.
//
// CIS AWS Foundations Benchmark: 2.1.1
func (s *S3Scanner) checkEncryption(ctx context.Context, bucket string) (*models.Finding, error) {
	_, err := s.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket),
	})

	// A non-nil error here means no encryption configuration exists.
	if err != nil {
		return s.newFinding(bucket,
			models.SeverityHigh,
			"S3 bucket does not have default server-side encryption enabled",
			"The bucket has no default encryption configuration. Objects uploaded "+
				"without explicit encryption headers will be stored in plaintext.",
			"Enable default server-side encryption on the bucket using SSE-S3 "+
				"(AES-256) or SSE-KMS. SSE-KMS is preferred as it provides key "+
				"management controls and CloudTrail audit logs for every key use.",
			"2.1.1",
		), nil
	}

	return nil, nil
}

// checkLogging detects whether S3 server access logging is enabled on the bucket.
//
// Why it matters: Access logs record every request made to a bucket (who accessed
// what, when, and from where). Without logs, you cannot investigate a data breach,
// detect exfiltration, or prove compliance during an audit. Logs should be
// delivered to a separate, write-protected bucket so an attacker cannot cover
// their tracks by deleting them.
//
// Not a numbered CIS AWS v1.4 control — best practice for SOC2/HIPAA.
func (s *S3Scanner) checkLogging(ctx context.Context, bucket string) (*models.Finding, error) {
	out, err := s.client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("getting logging config for %s: %w", bucket, err)
	}

	// LoggingEnabled is nil when logging has never been configured.
	if out.LoggingEnabled == nil {
		return s.newFinding(bucket,
			models.SeverityMedium,
			"S3 bucket server access logging is not enabled",
			"Server access logging is disabled. Without access logs, there is no "+
				"record of who accessed or modified objects in this bucket, making "+
				"incident investigation and compliance auditing impossible.",
			"Enable server access logging on the bucket and deliver logs to a "+
				"dedicated, write-protected logging bucket in the same region.",
			"",
		), nil
	}

	return nil, nil
}

// checkVersioning detects whether versioning is enabled on the bucket.
//
// Why it matters: Versioning preserves every version of every object. This
// protects against both accidental deletion and ransomware attacks (where an
// attacker overwrites or deletes objects). Without versioning, a single
// s3:DeleteObject call permanently destroys data with no recovery path.
//
// Not a numbered CIS AWS v1.4 control — best practice for ransomware resilience.
func (s *S3Scanner) checkVersioning(ctx context.Context, bucket string) (*models.Finding, error) {
	out, err := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("getting versioning config for %s: %w", bucket, err)
	}

	// Status is an empty string when versioning has never been enabled, and
	// "Suspended" when it was once on but has been turned off.
	if out.Status != types.BucketVersioningStatusEnabled {
		return s.newFinding(bucket,
			models.SeverityMedium,
			"S3 bucket versioning is not enabled",
			"Versioning is disabled or suspended. Objects can be permanently "+
				"deleted or overwritten with no way to recover previous versions. "+
				"This is exploited by ransomware that targets cloud storage.",
			"Enable versioning on the bucket. Pair it with an S3 Lifecycle policy "+
				"to expire old versions and control storage costs.",
			"",
		), nil
	}

	return nil, nil
}

// newFinding is a convenience constructor that fills in all the fields that are
// the same for every finding produced by this scanner, so individual check
// methods only need to supply what is unique to each misconfiguration.
func (s *S3Scanner) newFinding(
	bucket string,
	severity models.Severity,
	title, description, recommendation, cisControl string,
) *models.Finding {
	return &models.Finding{
		ID:           generateID(),
		ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", bucket),
		ResourceType: "AWS::S3::Bucket",
		ResourceName: bucket,
		Service:      s.ServiceName(),
		Severity:     severity,
		Title:        title,
		Description:  description,
		Recommendation: recommendation,
		CISControl:   cisControl,
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS"},
		// S3 is a global service but buckets live in a specific region.
		// Use the region the scanner was configured with as a best-effort value.
		// A more precise implementation would call GetBucketLocation per bucket.
		Region:    s.region,
		AccountID: s.accountID,
		Status:    models.StatusOpen,
		Timestamp: time.Now().UTC(),
	}
}

// =============================================================================
// New checks — CIS 2.1.2, 2.1.4, public ACL
// =============================================================================

// checkHTTPSPolicy detects S3 buckets that do not enforce HTTPS-only access
// via a bucket policy with a Deny on aws:SecureTransport = false.
//
// Why it matters (CIS 2.1.2):
// Without an HTTPS-enforcement policy, clients can send requests to the bucket
// over unencrypted HTTP. Data in transit — including object contents, object
// keys, and any pre-signed URL payloads — is visible to a network attacker.
// A bucket policy that explicitly denies non-HTTPS requests prevents this at
// the API level, regardless of what the client chooses to do.
func (s *S3Scanner) checkHTTPSPolicy(ctx context.Context, bucket string) (*models.Finding, error) {
	out, err := s.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		// NoSuchBucketPolicy means there is no policy at all — no HTTPS enforcement possible.
		return s.newFinding(bucket,
			models.SeverityHigh,
			"S3 bucket does not enforce HTTPS-only access",
			"The bucket has no bucket policy, so clients can access it over unencrypted HTTP. "+
				"Data in transit — object contents, keys, and metadata — is exposed to "+
				"network interception.",
			"Add a bucket policy that denies all requests where aws:SecureTransport is false. "+
				"Example condition: {\"Bool\": {\"aws:SecureTransport\": \"false\"}}. "+
				"Apply the Deny to both the bucket ARN and the /* resource.",
			"2.1.2",
		), nil
	}

	// If a policy exists, check whether it references aws:SecureTransport.
	// This is a conservative heuristic: if the policy contains this condition
	// key at all, assume it is correctly enforcing HTTPS.
	if !strings.Contains(aws.ToString(out.Policy), "aws:SecureTransport") {
		return s.newFinding(bucket,
			models.SeverityHigh,
			"S3 bucket policy does not enforce HTTPS-only access",
			"A bucket policy exists but does not contain an aws:SecureTransport condition. "+
				"Without this condition, clients can still access the bucket over HTTP even "+
				"though a policy is present.",
			"Update the bucket policy to include a Deny statement with condition "+
				"{\"Bool\": {\"aws:SecureTransport\": \"false\"}} applied to s3:* on both "+
				"the bucket and its objects.",
			"2.1.2",
		), nil
	}

	return nil, nil
}

// checkPublicACL detects S3 buckets whose ACL grants read or full-control
// access to the AllUsers group (the entire internet).
//
// Why it matters:
// S3 ACLs are a legacy access control mechanism. An ACL that grants READ or
// FULL_CONTROL to the AllUsers group (URI: .../AllUsers) makes every object in
// the bucket readable or writable by anyone on the internet without
// authentication. This is one of the most common causes of S3 data breaches.
// Note: Block Public Access settings should prevent this when fully enabled,
// but this check catches cases where Block Public Access is misconfigured.
func (s *S3Scanner) checkPublicACL(ctx context.Context, bucket string) (*models.Finding, error) {
	out, err := s.client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("getting ACL for %s: %w", bucket, err)
	}

	const allUsersURI = "http://acs.amazonaws.com/groups/global/AllUsers"

	for _, grant := range out.Grants {
		if grant.Grantee == nil {
			continue
		}
		if grant.Grantee.Type != types.TypeGroup {
			continue
		}
		if aws.ToString(grant.Grantee.URI) != allUsersURI {
			continue
		}
		// AllUsers has READ or FULL_CONTROL — this bucket is publicly accessible.
		perm := string(grant.Permission)
		return s.newFinding(bucket,
			models.SeverityCritical,
			"S3 bucket ACL grants public read access to the internet",
			fmt.Sprintf(
				"The bucket '%s' has an ACL entry that grants %s permission to the "+
					"AllUsers group (the entire internet). Any unauthenticated user can "+
					"access objects in this bucket. This is a leading cause of S3 data breaches.",
				bucket, perm),
			"Remove the public ACL grant from the bucket immediately. Enable all four "+
				"S3 Block Public Access settings to prevent any future ACL or policy from "+
				"re-exposing the bucket. Audit what data was in the bucket and treat the "+
				"exposure as a potential data breach.",
			"",
		), nil
	}

	return nil, nil
}

// checkMFADelete detects whether MFA Delete is enabled on the S3 bucket.
//
// Why it matters (S3.20):
// MFA Delete requires the bucket owner to provide a valid MFA token in addition
// to valid credentials when permanently deleting an object version or changing
// versioning state. Without it, a compromised set of access keys is sufficient
// to permanently destroy all versioned data — MFA Delete adds a physical second
// factor that prevents this even if credentials are leaked.
func (s *S3Scanner) checkMFADelete(ctx context.Context, bucket string) (*models.Finding, error) {
	out, err := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("getting versioning config for MFA delete check on %s: %w", bucket, err)
	}

	if out.MFADelete == types.MFADeleteStatusEnabled {
		return nil, nil
	}

	return s.newFinding(bucket,
		models.SeverityMedium,
		"S3 bucket does not have MFA Delete enabled",
		"MFA Delete is disabled on this bucket. Without it, permanently deleting versioned "+
			"objects or disabling versioning requires only a valid access key — a compromised "+
			"credential is sufficient to irreversibly destroy all object versions. MFA Delete "+
			"adds a physical second factor that must be present for destructive operations.",
		"Enable MFA Delete on the bucket using the root account credentials: "+
			"'aws s3api put-bucket-versioning --bucket "+bucket+" "+
			"--versioning-configuration Status=Enabled,MFADelete=Enabled "+
			"--mfa \"arn:aws:iam::ACCOUNT:mfa/DEVICE TOTP_CODE\"'. "+
			"Note: MFA Delete can only be enabled by the root account or an account with "+
			"explicit permission, and requires an active MFA device.",
		"S3.20",
	), nil
}

// generateID returns a random hex string suitable for use as a finding ID.
// We use crypto/rand (not math/rand) because security tooling should always
// use a cryptographically secure source of randomness.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
