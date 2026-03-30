package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"cspm-dashboard/backend/models"
)

const (
	// adminPolicyARN is the AWS-managed policy that grants unrestricted access
	// to every AWS service and resource.
	adminPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess"

	// accessKeyMaxAgeDays is the CIS-mandated maximum lifetime of an active
	// access key before it must be rotated.
	accessKeyMaxAgeDays = 90
)

// IAMScanner checks IAM configuration for account-wide and per-user security
// misconfigurations. Because IAM is a global service, all findings use "global"
// as their region — there is no region component in IAM resource ARNs.
//
// It implements the Scanner interface.
type IAMScanner struct {
	client    *iam.Client
	accountID string
}

// NewIAMScanner creates an IAMScanner from an already-configured AWS SDK config.
func NewIAMScanner(cfg aws.Config, accountID string) *IAMScanner {
	return &IAMScanner{
		client:    iam.NewFromConfig(cfg),
		accountID: accountID,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *IAMScanner) ServiceName() string { return "IAM" }

// Scan runs all IAM security checks and returns every finding detected.
//
// Structure: one account-level check (root keys) runs first, then all users are
// fetched once via pagination and the per-user checks iterate over that slice.
// Fetching users once avoids N extra ListUsers calls if more per-user checks
// are added later.
func (s *IAMScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// Account-level check — runs once, not per-user.
	rootFindings, err := s.checkRootAccessKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam: checking root access keys: %w", err)
	}
	findings = append(findings, rootFindings...)

	// Paginate through every IAM user once, then run all per-user checks.
	users, err := s.listAllUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam: listing users: %w", err)
	}

	for _, user := range users {
		username := aws.ToString(user.UserName)
		userARN := aws.ToString(user.Arn)

		// Each check returns its own slice so it can produce zero, one, or many
		// findings per user (e.g., a user with two stale keys → two findings).
		// Errors on individual users are skipped to keep the scan resilient.
		if fs, err := s.checkUserMFA(ctx, username, userARN); err == nil {
			findings = append(findings, fs...)
		}
		if fs, err := s.checkAdminPoliciesOnUser(ctx, username, userARN); err == nil {
			findings = append(findings, fs...)
		}
		if fs, err := s.checkAccessKeyAge(ctx, username, userARN); err == nil {
			findings = append(findings, fs...)
		}
	}

	return findings, nil
}

// listAllUsers returns every IAM user in the account by walking the paginated
// ListUsers API. Pagination is a recurring pattern across AWS APIs — any
// response with IsTruncated=true has more pages reachable via the Marker field.
// The SDK v2 paginator handles that bookkeeping automatically.
func (s *IAMScanner) listAllUsers(ctx context.Context) ([]types.User, error) {
	var users []types.User
	paginator := iam.NewListUsersPaginator(s.client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		users = append(users, page.Users...)
	}
	return users, nil
}

// checkRootAccessKeys detects whether the AWS root account has active
// programmatic access keys.
//
// Why it matters: The root account bypasses all IAM permission boundaries — no
// policy can restrict it, no SCP can block it, and no permission boundary can
// constrain it. An access key for root is the single most dangerous credential
// in an AWS account. It cannot be scoped, and compromise means total account
// takeover. Root should use the console with MFA only; it must never have
// programmatic credentials.
//
// GetAccountSummary is an efficient way to detect this: it returns a flat map
// of account-wide IAM counters without needing to enumerate credentials directly.
//
// CIS AWS Foundations Benchmark: 1.4
func (s *IAMScanner) checkRootAccessKeys(ctx context.Context) ([]models.Finding, error) {
	out, err := s.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}

	// AccountAccessKeysPresent is the number of active root access keys (0 or 1).
	// The map key type is string, so we cast the typed constant to index it.
	if out.SummaryMap[string(types.SummaryKeyTypeAccountAccessKeysPresent)] > 0 {
		rootARN := fmt.Sprintf("arn:aws:iam::%s:root", s.accountID)
		return []models.Finding{s.newFinding(
			rootARN, "AWS::IAM::Root", "root",
			models.SeverityCritical,
			"Root account has active access keys",
			"The AWS root account has one or more active programmatic access keys. "+
				"Root credentials cannot be restricted by IAM policies, SCPs, or "+
				"permission boundaries. An attacker with these keys has unrestricted "+
				"control over the entire account, including the ability to delete all "+
				"IAM principals, disable CloudTrail, and access all data.",
			"Delete all root account access keys immediately via the AWS console "+
				"under My Security Credentials. Operational tasks that currently use "+
				"root keys should be migrated to least-privilege IAM roles or service "+
				"accounts. Root should only ever be used interactively with MFA for "+
				"the handful of tasks that genuinely require it (e.g., closing the account).",
			"1.4",
		)}, nil
	}

	return nil, nil
}

// checkUserMFA detects IAM users who can log into the AWS console but have not
// enrolled an MFA device.
//
// Why it matters: A password is a single factor. Credential stuffing, phishing,
// and password-spraying attacks are all trivially blocked by MFA. Without it, a
// leaked or guessed password gives an attacker full console access and everything
// the user is permitted to do. AWS account takeovers most commonly start with a
// console login using a stolen password on an account without MFA.
//
// Two API calls are needed per user:
//  1. GetLoginProfile — determines if the user has a console password at all.
//     Programmatic-only users (no password) don't need MFA for the console.
//  2. ListMFADevices — checks whether at least one MFA device is enrolled.
//
// CIS AWS Foundations Benchmark: 1.10
func (s *IAMScanner) checkUserMFA(ctx context.Context, username, userARN string) ([]models.Finding, error) {
	// Step 1: does this user have a console password?
	_, err := s.client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil {
		// NoSuchEntityException means no login profile exists — this user is
		// programmatic-only and MFA on the console does not apply to them.
		var noSuchEntity *types.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting login profile for %s: %w", username, err)
	}

	// Step 2: user has console access — verify they have an MFA device.
	mfaOut, err := s.client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing MFA devices for %s: %w", username, err)
	}

	if len(mfaOut.MFADevices) == 0 {
		return []models.Finding{s.newFinding(
			userARN, "AWS::IAM::User", username,
			models.SeverityHigh,
			"IAM user with console access has no MFA device enrolled",
			fmt.Sprintf(
				"User '%s' can log into the AWS console with a password but has no "+
					"MFA device. A stolen or guessed password alone is sufficient for an "+
					"attacker to access the console and act with the full permissions of "+
					"this user.",
				username),
			fmt.Sprintf(
				"Enroll a virtual MFA device (e.g., Google Authenticator) or a hardware "+
					"token for user '%s'. To enforce MFA programmatically, attach an IAM "+
					"policy that denies all actions except iam:CreateVirtualMFADevice and "+
					"iam:EnableMFADevice unless aws:MultiFactorAuthPresent is true.",
				username),
			"1.10",
		)}, nil
	}

	return nil, nil
}

// checkAdminPoliciesOnUser detects full administrative access granted directly
// to an IAM user rather than through a group or role.
//
// Why it matters: Attaching admin access directly to a user creates a tight
// coupling between a human identity and a highly privileged permission set.
// Groups and roles decouple identity from permissions: they are easier to
// audit, easier to revoke when a user leaves, and less likely to be overlooked
// during access reviews. Direct admin attachments also inflate blast radius —
// a compromised user immediately has unrestricted account access with no
// additional step required.
//
// Two sub-cases are checked:
//  1. The AWS-managed AdministratorAccess policy attached directly to the user.
//  2. An inline policy embedded in the user that grants Effect:Allow, Action:*,
//     Resource:* (functionally equivalent to AdministratorAccess).
//
// Note: a production scanner would also inspect customer-managed policies
// attached to the user by fetching and parsing each policy's default version
// document. That is omitted here to keep the example readable.
//
// CIS AWS Foundations Benchmark: 1.16
func (s *IAMScanner) checkAdminPoliciesOnUser(ctx context.Context, username, userARN string) ([]models.Finding, error) {
	var findings []models.Finding

	// --- Sub-check A: managed policies directly attached to the user ---
	attachedOut, err := s.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing attached policies for %s: %w", username, err)
	}

	for _, policy := range attachedOut.AttachedPolicies {
		if aws.ToString(policy.PolicyArn) == adminPolicyARN {
			findings = append(findings, s.newFinding(
				userARN, "AWS::IAM::User", username,
				models.SeverityHigh,
				"IAM user has AdministratorAccess policy attached directly",
				fmt.Sprintf(
					"User '%s' has the AWS-managed AdministratorAccess policy attached "+
						"directly to them, granting unrestricted access to all AWS services "+
						"and resources. Direct attachment bypasses group-based access control "+
						"and makes permission reviews harder to perform systematically.",
					username),
				fmt.Sprintf(
					"Remove AdministratorAccess from user '%s'. If broad access is "+
						"genuinely required, grant it via an IAM group so all similarly "+
						"privileged users are managed in one place, or use an IAM role with "+
						"a short session duration and an MFA condition on assumption.",
					username),
				"1.16",
			))
		}
	}

	// --- Sub-check B: inline policies embedded in the user ---
	// Inline policies are often overlooked in access reviews because they are
	// not visible in the IAM Policies list — you must inspect each user directly.
	inlineOut, err := s.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing inline policies for %s: %w", username, err)
	}

	for _, policyName := range inlineOut.PolicyNames {
		policyOut, err := s.client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
			UserName:   aws.String(username),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			continue // skip unreadable policies rather than failing the whole scan
		}

		// IAM returns inline policy documents URL-encoded. Decode before parsing.
		doc, err := url.QueryUnescape(aws.ToString(policyOut.PolicyDocument))
		if err != nil {
			continue
		}

		if isAdminPolicy(doc) {
			findings = append(findings, s.newFinding(
				userARN, "AWS::IAM::User", username,
				models.SeverityHigh,
				"IAM user has inline policy granting full admin access",
				fmt.Sprintf(
					"User '%s' has an inline policy named '%s' that grants Effect:Allow "+
						"on Action:* and Resource:*. This is functionally identical to "+
						"AdministratorAccess and violates the principle of least privilege.",
					username, policyName),
				fmt.Sprintf(
					"Delete inline policy '%s' from user '%s' and replace it with a "+
						"scoped managed policy that grants only the specific permissions "+
						"required. Assign permissions via an IAM group rather than directly "+
						"to the user.",
					policyName, username),
				"1.16",
			))
		}
	}

	return findings, nil
}

// checkAccessKeyAge detects active access keys that have not been rotated
// within the past 90 days.
//
// Why it matters: Access keys are long-lived static credentials. The longer a
// key exists, the greater the chance it has been silently compromised — leaked
// to source control, copied from a config file, or harvested from a developer
// machine. Regular rotation limits the window of exploitation: even if a key
// was stolen months ago, rotating it revokes the attacker's access immediately.
// The 90-day limit in CIS reflects the industry consensus on acceptable key age.
//
// Only active keys are checked. Inactive keys (Status: Inactive) should ideally
// be deleted entirely, but that is covered by CIS 1.12 (a separate check).
//
// CIS AWS Foundations Benchmark: 1.14
func (s *IAMScanner) checkAccessKeyAge(ctx context.Context, username, userARN string) ([]models.Finding, error) {
	var findings []models.Finding

	keysOut, err := s.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing access keys for %s: %w", username, err)
	}

	for _, key := range keysOut.AccessKeyMetadata {
		// Inactive keys don't pose an active threat — skip them.
		if key.Status != types.StatusTypeActive {
			continue
		}

		age := time.Since(aws.ToTime(key.CreateDate))
		if age > accessKeyMaxAgeDays*24*time.Hour {
			keyID := aws.ToString(key.AccessKeyId)
			ageDays := int(age.Hours() / 24)

			findings = append(findings, s.newFinding(
				// The finding targets the key itself, not the user, so the resource
				// name is the key ID. This makes it unambiguous which key to rotate
				// when a user has two keys (AWS allows a maximum of two per user).
				userARN, "AWS::IAM::AccessKey", keyID,
				models.SeverityMedium,
				"IAM access key has not been rotated in over 90 days",
				fmt.Sprintf(
					"Access key '%s' belonging to user '%s' is %d days old and has "+
						"not been rotated. Long-lived credentials increase the risk of "+
						"undetected compromise. If this key was leaked, an attacker may "+
						"have had silent access for months.",
					keyID, username, ageDays),
				fmt.Sprintf(
					"Rotate key '%s' for user '%s': (1) create a new access key, "+
						"(2) update all applications or CI/CD pipelines using the old key, "+
						"(3) verify the new key works in all systems, (4) deactivate the "+
						"old key and monitor for breakage, (5) delete the old key after a "+
						"short verification window. Consider storing keys in AWS Secrets "+
						"Manager with automatic rotation enabled.",
					keyID, username),
				"1.14",
			))
		}
	}

	return findings, nil
}

// newFinding is a convenience constructor that fills in the fields shared by
// every finding this scanner produces. IAM is a global service so Region is
// always "global" — IAM resource ARNs have no region component (note the
// double colon in arn:aws:iam::account-id:...).
func (s *IAMScanner) newFinding(
	resourceID, resourceType, resourceName string,
	severity models.Severity,
	title, description, recommendation, cisControl string,
) models.Finding {
	return models.Finding{
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
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST"},
		Region:               "global",
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// =============================================================================
// Policy document parsing
// =============================================================================

// policyDocument mirrors the top-level structure of an IAM policy JSON document.
// Only the fields needed for the admin-access check are decoded.
type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

// policyStatement represents one statement block within a policy document.
// Action and Resource use stringOrSlice because IAM allows both forms:
//
//	"Action": "*"            (single string)
//	"Action": ["s3:*", "*"]  (array of strings)
type policyStatement struct {
	Effect   string        `json:"Effect"`
	Action   stringOrSlice `json:"Action"`
	Resource stringOrSlice `json:"Resource"`
}

// stringOrSlice is a JSON-compatible type that unmarshals either a bare JSON
// string or a JSON array of strings into a []string. This is necessary because
// IAM policy documents permit both representations for Action and Resource,
// and the standard json package cannot unmarshal both into the same field type.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	// Attempt array form first.
	var slice []string
	if err := json.Unmarshal(data, &slice); err == nil {
		*s = slice
		return nil
	}
	// Fall back to single string form.
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = []string{str}
	return nil
}

// isAdminPolicy returns true if the policy document JSON contains at least one
// statement that grants Allow on both Action:* and Resource:*, which is the
// definition of unrestricted administrative access.
func isAdminPolicy(document string) bool {
	var doc policyDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		// If the document cannot be parsed, treat it as non-admin. Producing a
		// false negative is safer than a false positive that causes alert fatigue.
		return false
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if containsWildcard(stmt.Action) && containsWildcard(stmt.Resource) {
			return true
		}
	}
	return false
}

// containsWildcard returns true if any entry in values is a bare "*".
func containsWildcard(values []string) bool {
	for _, v := range values {
		if v == "*" {
			return true
		}
	}
	return false
}
