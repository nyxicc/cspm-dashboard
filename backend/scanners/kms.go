package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"cspm-dashboard/backend/models"
)

// KMSScanner checks every customer-managed KMS key in the region for two
// controls: automatic rotation disabled and public access via key policy.
// It implements the Scanner interface.
type KMSScanner struct {
	client    *kms.Client
	accountID string
	region    string
}

// NewKMSScanner creates a KMSScanner from an already-configured AWS SDK config.
func NewKMSScanner(cfg aws.Config, accountID string) *KMSScanner {
	return &KMSScanner{
		client:    kms.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *KMSScanner) ServiceName() string { return "KMS" }

// Scan paginates over every KMS key in the region. AWS-managed keys (created
// by services on your behalf) are skipped — only customer-managed keys (CMKs)
// that are in the Enabled state are inspected.
func (s *KMSScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	paginator := kms.NewListKeysPaginator(s.client, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("kms: listing keys: %w", err)
		}

		for _, keyEntry := range page.Keys {
			keyID := aws.ToString(keyEntry.KeyId)

			// DescribeKey returns full metadata including KeyManager and KeyState.
			desc, err := s.client.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: aws.String(keyID),
			})
			if err != nil {
				continue // skip inaccessible keys
			}

			meta := desc.KeyMetadata

			// Only check customer-managed keys that are actively enabled.
			// AWS-managed keys (KeyManager == AWS) are fully managed by AWS and
			// do not support customer-controlled rotation policies.
			if meta.KeyManager != kmstypes.KeyManagerTypeCustomer {
				continue
			}
			if meta.KeyState != kmstypes.KeyStateEnabled {
				continue // pending deletion, disabled, etc. — not our concern here
			}

			if f := s.checkRotation(ctx, meta); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkPublicPolicy(ctx, meta); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

// checkRotation detects customer-managed KMS keys that do not have automatic
// annual key rotation enabled.
//
// Why it matters (CIS 3.8):
// Regular key rotation limits the amount of data encrypted under a single key
// version. If a key is compromised, an attacker can only decrypt data encrypted
// after the most recent rotation, not all historical data. AWS KMS annual
// rotation is free, transparent to applications (old key versions are retained
// for decryption), and requires no operational changes.
//
// Some key types do not support automatic rotation (asymmetric keys, imported
// key material). UnsupportedOperationException from GetKeyRotationStatus is
// handled gracefully — those keys are skipped.
func (s *KMSScanner) checkRotation(ctx context.Context, meta *kmstypes.KeyMetadata) *models.Finding {
	keyID := aws.ToString(meta.KeyId)

	rotOut, err := s.client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		var unsupported *kmstypes.UnsupportedOperationException
		if errors.As(err, &unsupported) {
			return nil // asymmetric or imported key — rotation not applicable
		}
		return nil // skip on other errors rather than false-positive
	}

	if rotOut.KeyRotationEnabled {
		return nil
	}

	keyARN := aws.ToString(meta.Arn)
	alias := s.aliasOrID(meta)

	return s.newFinding(keyARN, alias,
		models.SeverityMedium,
		"KMS customer-managed key does not have automatic rotation enabled",
		fmt.Sprintf(
			"KMS key '%s' (%s) does not have automatic annual rotation enabled. "+
				"Without rotation, the same key material is used indefinitely. If the "+
				"key is ever compromised, all data encrypted under it — including "+
				"historical data — is at risk of decryption.",
			alias, keyID),
		fmt.Sprintf(
			"Enable automatic rotation for key '%s': "+
				"'aws kms enable-key-rotation --key-id %s'. "+
				"Annual rotation is free, transparent to applications, and retains "+
				"old key versions so previously encrypted data can still be decrypted.",
			alias, keyID),
		"3.8",
	)
}

// checkPublicPolicy detects KMS keys whose default key policy contains an
// Allow statement with a wildcard Principal ("*"), granting any AWS principal
// — including unauthenticated principals — access to the key.
//
// Why it matters:
// A KMS key policy with Principal:"*" in an Allow statement makes the key
// accessible to any AWS account or anonymous request that meets the conditions.
// This can expose the ability to encrypt or decrypt data to entities outside
// the account, which is almost never intentional and can enable data exfiltration
// or key misuse by third parties.
func (s *KMSScanner) checkPublicPolicy(ctx context.Context, meta *kmstypes.KeyMetadata) *models.Finding {
	keyID := aws.ToString(meta.KeyId)

	pOut, err := s.client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return nil // skip if policy is unreadable
	}

	if !kmsKeyPolicyIsPublic(aws.ToString(pOut.Policy)) {
		return nil
	}

	keyARN := aws.ToString(meta.Arn)
	alias := s.aliasOrID(meta)

	return s.newFinding(keyARN, alias,
		models.SeverityCritical,
		"KMS key policy grants public access via wildcard principal",
		fmt.Sprintf(
			"KMS key '%s' (%s) has a key policy with an Allow statement whose "+
				"Principal is set to '*'. This grants any AWS principal — including "+
				"principals in other accounts — the ability to use the key for "+
				"cryptographic operations, potentially enabling unauthorised decryption "+
				"of data protected by this key.",
			alias, keyID),
		fmt.Sprintf(
			"Update the key policy for '%s' to restrict the Principal to specific "+
				"IAM principals, roles, or accounts that genuinely need access. "+
				"Never use '*' as a Principal in an Allow statement unless combined "+
				"with restrictive Condition clauses that limit the scope.",
			alias),
		"",
	)
}

// aliasOrID returns the key's Description if non-empty, otherwise the key ID.
// KMS keys do not have a Name field — aliases are separate resources.
func (s *KMSScanner) aliasOrID(meta *kmstypes.KeyMetadata) string {
	if desc := aws.ToString(meta.Description); desc != "" {
		return desc
	}
	return aws.ToString(meta.KeyId)
}

// newFinding constructs a KMS finding with all shared fields populated.
func (s *KMSScanner) newFinding(
	resourceID, resourceName string,
	severity models.Severity,
	title, description, recommendation, cisControl string,
) *models.Finding {
	return &models.Finding{
		ID:                   generateID(),
		ResourceID:           resourceID,
		ResourceType:         "AWS::KMS::Key",
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
// KMS key policy parser
// =============================================================================

// kmsKeyPolicy mirrors only the fields needed to detect a public principal.
type kmsKeyPolicy struct {
	Statement []kmsStatement `json:"Statement"`
}

type kmsStatement struct {
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"` // "*" (string) or {"AWS": "..."} (object)
}

// kmsKeyPolicyIsPublic returns true if the policy JSON contains at least one
// Allow statement where Principal is the bare wildcard "*" or an object whose
// AWS value includes "*".
func kmsKeyPolicyIsPublic(policyJSON string) bool {
	var policy kmsKeyPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return false
	}

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		switch p := stmt.Principal.(type) {
		case string:
			if p == "*" {
				return true
			}
		case map[string]interface{}:
			for _, v := range p {
				switch val := v.(type) {
				case string:
					if val == "*" {
						return true
					}
				case []interface{}:
					for _, item := range val {
						if s, ok := item.(string); ok && s == "*" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
