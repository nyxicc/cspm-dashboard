package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
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

	// Account-level checks — run once, not per-user.
	rootFindings, err := s.checkRootAccessKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam: checking root access keys: %w", err)
	}
	findings = append(findings, rootFindings...)

	// CIS 1.5 — root MFA.
	if fs, err := s.checkRootMFA(ctx); err == nil {
		findings = append(findings, fs...)
	}

	// Account-level: password policy checks (CIS 1.8, 1.9).
	if fs, err := s.checkPasswordPolicy(ctx); err == nil {
		findings = append(findings, fs...)
	}

	// IAM.6 — hardware MFA for root.
	if fs, err := s.checkRootHardwareMFA(ctx); err == nil {
		findings = append(findings, fs...)
	}

	// IAM.18 — support role must exist.
	if fs, err := s.checkSupportRoleExists(ctx); err == nil {
		findings = append(findings, fs...)
	}

	// IAM.26 — expired SSL/TLS certificates.
	if fs, err := s.checkExpiredServerCertificates(ctx); err == nil {
		findings = append(findings, fs...)
	}

	// IAM.27 — AWSCloudShellFullAccess.
	if fs, err := s.checkCloudShellFullAccess(ctx); err == nil {
		findings = append(findings, fs...)
	}

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
		if fs, err := s.checkInactiveUser(ctx, user); err == nil {
			findings = append(findings, fs...)
		}
		if fs, err := s.checkUserConsoleAndKeys(ctx, username, userARN); err == nil {
			findings = append(findings, fs...)
		}
		if fs, err := s.checkSingleActiveAccessKey(ctx, username, userARN); err == nil {
			findings = append(findings, fs...)
		}
		if fs, err := s.checkPermissionsOnlyThroughGroups(ctx, username, userARN); err == nil {
			findings = append(findings, fs...)
		}
		if fs, err := s.checkCredentialsUnused45Days(ctx, user); err == nil {
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

// =============================================================================
// New checks — CIS 1.5, 1.8, 1.9, 1.11, 1.12, 1.13, 1.15
// =============================================================================

// checkPasswordPolicy fetches the account-level IAM password policy and emits
// a finding for each CIS requirement that is not met.
//
// CIS 1.8 covers minimum length and complexity; CIS 1.9 covers reuse
// prevention and expiration. If no policy exists at all, a single
// comprehensive finding is returned and the individual sub-checks are skipped.
func (s *IAMScanner) checkPasswordPolicy(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding
	arn := fmt.Sprintf("arn:aws:iam::%s:account", s.accountID)

	out, err := s.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		var noSuchEntity *types.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			// No policy at all — one finding covers all four sub-checks.
			findings = append(findings, s.newFinding(
				arn, "AWS::IAM::PasswordPolicy", "account-password-policy",
				models.SeverityHigh,
				"No IAM account password policy is configured",
				"No IAM password policy is set for this account. Without one, IAM users "+
					"can set passwords of any length and complexity, passwords never expire, "+
					"and previously used passwords can be reused immediately. This violates "+
					"CIS controls 1.8 and 1.9.",
				"Create an IAM account password policy that enforces: minimum length 14+, "+
					"uppercase, lowercase, numbers, and symbols required, password reuse "+
					"prevention of 24+, and a maximum password age of 90 days.",
				"1.8",
			))
			return findings, nil
		}
		return nil, err
	}

	p := out.PasswordPolicy

	// CIS 1.8 — minimum password length >= 14.
	if aws.ToInt32(p.MinimumPasswordLength) < 14 {
		findings = append(findings, s.newFinding(
			arn, "AWS::IAM::PasswordPolicy", "account-password-policy",
			models.SeverityMedium,
			"IAM password policy minimum length is less than 14 characters",
			fmt.Sprintf(
				"The account password policy requires a minimum of %d characters. "+
					"CIS recommends at least 14 to reduce susceptibility to brute-force attacks.",
				aws.ToInt32(p.MinimumPasswordLength)),
			"Update the IAM account password policy to require a minimum length of 14 characters.",
			"1.8",
		))
	}

	// CIS 1.8 — all four complexity requirements must be enabled.
	var missing []string
	if !p.RequireUppercaseCharacters {
		missing = append(missing, "uppercase letters")
	}
	if !p.RequireLowercaseCharacters {
		missing = append(missing, "lowercase letters")
	}
	if !p.RequireNumbers {
		missing = append(missing, "numbers")
	}
	if !p.RequireSymbols {
		missing = append(missing, "symbols")
	}
	if len(missing) > 0 {
		findings = append(findings, s.newFinding(
			arn, "AWS::IAM::PasswordPolicy", "account-password-policy",
			models.SeverityMedium,
			"IAM password policy does not enforce all complexity requirements",
			fmt.Sprintf(
				"The password policy is missing complexity requirements for: %s. "+
					"Complex passwords significantly reduce susceptibility to dictionary attacks.",
				strings.Join(missing, ", ")),
			"Update the IAM account password policy to require uppercase, lowercase, numbers, and symbols.",
			"1.8",
		))
	}

	// CIS 1.9 — password reuse prevention >= 24.
	if aws.ToInt32(p.PasswordReusePrevention) < 24 {
		findings = append(findings, s.newFinding(
			arn, "AWS::IAM::PasswordPolicy", "account-password-policy",
			models.SeverityMedium,
			"IAM password policy does not prevent sufficient password reuse",
			fmt.Sprintf(
				"The policy only prevents reuse of the last %d passwords. "+
					"CIS requires at least 24 to prevent users from cycling through a small set.",
				aws.ToInt32(p.PasswordReusePrevention)),
			"Update the IAM account password policy to prevent reuse of the last 24 passwords.",
			"1.9",
		))
	}

	// CIS 1.9 — passwords must expire.
	if !p.ExpirePasswords {
		findings = append(findings, s.newFinding(
			arn, "AWS::IAM::PasswordPolicy", "account-password-policy",
			models.SeverityMedium,
			"IAM password policy does not require password expiration",
			"The account password policy does not require users to change their passwords "+
				"periodically. Without expiration, a stolen password remains valid indefinitely.",
			"Update the IAM account password policy to set a maximum password age of 90 days or less.",
			"1.9",
		))
	}

	return findings, nil
}

// checkRootMFA detects whether multi-factor authentication is enabled on the
// AWS root account.
//
// Why it matters (CIS 1.5):
// The root account has unrestricted access to every AWS service and resource —
// it cannot be limited by IAM policies, SCPs, or permission boundaries. A stolen
// root password without MFA gives an attacker total, permanent control over the
// account. Root MFA is one of the single highest-value security controls.
func (s *IAMScanner) checkRootMFA(ctx context.Context) ([]models.Finding, error) {
	out, err := s.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}

	if out.SummaryMap[string(types.SummaryKeyTypeAccountMFAEnabled)] == 0 {
		rootARN := fmt.Sprintf("arn:aws:iam::%s:root", s.accountID)
		return []models.Finding{s.newFinding(
			rootARN, "AWS::IAM::Root", "root",
			models.SeverityCritical,
			"Root account does not have MFA enabled",
			"The AWS root account has no MFA device enrolled. The root account bypasses "+
				"all IAM permission boundaries and cannot be constrained by any policy. "+
				"A stolen root password without MFA grants total, unrestricted control "+
				"over the entire account and all its resources.",
			"Enable hardware MFA on the root account immediately via the AWS console "+
				"under My Security Credentials. A hardware TOTP token is preferred over "+
				"virtual MFA because it cannot be phished. The root account should only "+
				"be used for the handful of tasks that genuinely require it.",
			"1.5",
		)}, nil
	}
	return nil, nil
}

// checkSingleActiveAccessKey detects IAM users with more than one active access key.
//
// Why it matters (CIS 1.13):
// AWS allows each IAM user to have up to two access keys. Having two active keys
// simultaneously doubles the attack surface: a leaked key is harder to identify
// and rotate, key age policies become ambiguous, and CloudTrail attribution is
// more complex. Maintaining only one active key enforces a clean rotation discipline.
func (s *IAMScanner) checkSingleActiveAccessKey(ctx context.Context, username, userARN string) ([]models.Finding, error) {
	keysOut, err := s.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing access keys for %s: %w", username, err)
	}

	activeCount := 0
	for _, key := range keysOut.AccessKeyMetadata {
		if key.Status == types.StatusTypeActive {
			activeCount++
		}
	}

	if activeCount > 1 {
		return []models.Finding{s.newFinding(
			userARN, "AWS::IAM::User", username,
			models.SeverityMedium,
			"IAM user has more than one active access key",
			fmt.Sprintf(
				"User '%s' has %d active access keys. CIS 1.13 requires that each user "+
					"have at most one active key. Multiple active keys increase the chance "+
					"that a leaked key goes undetected and complicate rotation procedures.",
				username, activeCount),
			fmt.Sprintf(
				"Check which access key for user '%s' is in active use by reviewing "+
					"LastUsedDate in the IAM console. Deactivate the older or unused key, "+
					"confirm no breakage, then delete it. Limit each user to one active key at all times.",
				username),
			"1.13",
		)}, nil
	}

	return nil, nil
}

// checkPermissionsOnlyThroughGroups detects IAM users who have managed policies
// attached directly to them rather than through IAM groups.
//
// Why it matters (CIS 1.15):
// Direct policy attachments make permissions harder to audit, revoke at scale,
// and govern consistently. When permissions are managed through groups, access
// reviews are simple: remove the user from the group. Direct attachments must
// be hunted individually across every user in the account.
func (s *IAMScanner) checkPermissionsOnlyThroughGroups(ctx context.Context, username, userARN string) ([]models.Finding, error) {
	attachedOut, err := s.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing attached policies for %s: %w", username, err)
	}

	if len(attachedOut.AttachedPolicies) == 0 {
		return nil, nil
	}

	names := make([]string, 0, len(attachedOut.AttachedPolicies))
	for _, p := range attachedOut.AttachedPolicies {
		names = append(names, aws.ToString(p.PolicyName))
	}

	plural := "y"
	if len(names) != 1 {
		plural = "ies"
	}

	return []models.Finding{s.newFinding(
		userARN, "AWS::IAM::User", username,
		models.SeverityMedium,
		"IAM user has managed policies attached directly instead of through a group",
		fmt.Sprintf(
			"User '%s' has %d managed polic%s attached directly: %s. "+
				"CIS 1.15 requires all permissions to flow through IAM groups so that "+
				"access can be managed, audited, and revoked centrally.",
			username, len(names), plural, strings.Join(names, ", ")),
		fmt.Sprintf(
			"Remove the directly attached policies from user '%s'. Create or identify "+
				"an IAM group with the equivalent permissions and add the user to that group. "+
				"If multiple users share the same role, this approach also eliminates "+
				"per-user permission drift.",
			username),
		"1.15",
	)}, nil
}

// checkInactiveUser detects IAM users whose console credentials have not been
// used for 90 days or more (or have never been used on an account older than 90 days).
//
// Why it matters (CIS 1.12):
// Stale credentials are a persistent risk — the user may have left the organisation
// but their password remains valid. CIS requires that credentials unused for 90+
// days be disabled to prevent silent exploitation of dormant accounts.
func (s *IAMScanner) checkInactiveUser(ctx context.Context, user types.User) ([]models.Finding, error) {
	username := aws.ToString(user.UserName)
	userARN := aws.ToString(user.Arn)

	// Only check users who have console access — programmatic-only users
	// do not log into the console so inactivity here is not meaningful.
	_, err := s.client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil {
		var noSuchEntity *types.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			return nil, nil // no console password, skip
		}
		return nil, fmt.Errorf("getting login profile for %s: %w", username, err)
	}

	const threshold = 90 * 24 * time.Hour
	createDate := aws.ToTime(user.CreateDate)

	// If the account itself is newer than 90 days, do not flag — the user
	// simply has not had enough time to establish an activity pattern.
	if time.Since(createDate) <= threshold {
		return nil, nil
	}

	lastUsed := aws.ToTime(user.PasswordLastUsed)

	if lastUsed.IsZero() {
		// PasswordLastUsed is nil — user has never logged in despite account being 90+ days old.
		return []models.Finding{s.newFinding(
			userARN, "AWS::IAM::User", username,
			models.SeverityHigh,
			"IAM user credentials unused for 90+ days (never logged in)",
			fmt.Sprintf(
				"User '%s' has had a console password for over 90 days but has never logged in. "+
					"CIS 1.12 requires that credentials unused for 90 days or more be disabled. "+
					"Unused accounts with persistent credentials expand the attack surface.",
				username),
			fmt.Sprintf(
				"Disable or delete user '%s' if they no longer need access. If the account "+
					"is legitimately needed, remove the console password and require role "+
					"assumption with MFA instead.",
				username),
			"1.12",
		)}, nil
	}

	if time.Since(lastUsed) > threshold {
		daysSince := int(time.Since(lastUsed).Hours() / 24)
		return []models.Finding{s.newFinding(
			userARN, "AWS::IAM::User", username,
			models.SeverityHigh,
			fmt.Sprintf("IAM user credentials unused for %d days", daysSince),
			fmt.Sprintf(
				"User '%s' last logged into the console %d days ago. CIS 1.12 requires "+
					"that credentials unused for 90+ days be disabled. Stale accounts are a "+
					"common attacker foothold because dormant logins are less likely to "+
					"trigger anomaly detection or be noticed during incident response.",
				username, daysSince),
			fmt.Sprintf(
				"Disable the console password for user '%s' or delete the account if they "+
					"no longer need access. If access is still required, verify MFA enrollment "+
					"and consider AWS IAM Identity Center with time-bounded access.",
				username),
			"1.12",
		)}, nil
	}

	return nil, nil
}

// checkUserConsoleAndKeys detects IAM users who have both a console password
// and at least one active programmatic access key.
//
// Why it matters (CIS 1.11):
// Human users should authenticate via the console or SSO. Service accounts that
// need programmatic access should never have a console password. Combining both
// on the same identity means a single compromised credential (either the
// password or the access key) grants the attacker the full range of what the
// user can do. Separation reduces blast radius.
func (s *IAMScanner) checkUserConsoleAndKeys(ctx context.Context, username, userARN string) ([]models.Finding, error) {
	// Step 1: does this user have a console password?
	_, err := s.client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil {
		var noSuchEntity *types.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			return nil, nil // no console password, skip
		}
		return nil, fmt.Errorf("getting login profile for %s: %w", username, err)
	}

	// Step 2: count active access keys.
	keysOut, err := s.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing access keys for %s: %w", username, err)
	}

	activeKeys := 0
	for _, k := range keysOut.AccessKeyMetadata {
		if k.Status == types.StatusTypeActive {
			activeKeys++
		}
	}
	if activeKeys == 0 {
		return nil, nil
	}

	return []models.Finding{s.newFinding(
		userARN, "AWS::IAM::User", username,
		models.SeverityMedium,
		"IAM user has both console password and active access keys",
		fmt.Sprintf(
			"User '%s' has a console password and %d active access key(s). "+
				"Combining both credential types on a single identity increases blast radius: "+
				"compromise of either grants the attacker the user's full set of permissions. "+
				"Human users should authenticate via console/SSO only; programmatic access "+
				"should use dedicated service accounts or IAM roles.",
			username, activeKeys),
		fmt.Sprintf(
			"For user '%s': if they are a human user, revoke the access keys and use "+
				"IAM Identity Center or role assumption for any programmatic needs. "+
				"If they are a service account, remove the console password.",
			username),
		"1.11",
	)}, nil
}

// checkRootHardwareMFA detects whether the root account is using virtual MFA
// instead of a hardware MFA device.
// IAM.6: Hardware MFA should be enabled for the root user.
func (s *IAMScanner) checkRootHardwareMFA(ctx context.Context) ([]models.Finding, error) {
	summaryOut, err := s.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	// If root has no MFA at all, IAM.9 / checkRootMFA already covers it.
	if summaryOut.SummaryMap[string(types.SummaryKeyTypeAccountMFAEnabled)] == 0 {
		return nil, nil
	}

	// Root has MFA — determine whether it's virtual (bad) or hardware (good).
	vMFAOut, err := s.client.ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{
		AssignmentStatus: types.AssignmentStatusTypeAssigned,
	})
	if err != nil {
		return nil, err
	}

	rootARN := fmt.Sprintf("arn:aws:iam::%s:root", s.accountID)
	for _, device := range vMFAOut.VirtualMFADevices {
		serial := aws.ToString(device.SerialNumber)
		if strings.Contains(serial, ":mfa/root-account-mfa-device") {
			return []models.Finding{s.newFinding(
				rootARN, "AWS::IAM::Root", "root",
				models.SeverityHigh,
				"Root account is using virtual MFA instead of hardware MFA",
				"The root account has a virtual MFA device enrolled. Virtual MFA is software-based "+
					"and can be compromised if the device running the authenticator app is stolen or "+
					"phished. Hardware MFA tokens are physically bound and cannot be remotely exfiltrated.",
				"Replace the virtual MFA on the root account with a hardware TOTP security key "+
					"(e.g., YubiKey or Gemalto token). Disable the virtual device after the hardware "+
					"token is enrolled and tested.",
				"IAM.6",
			)}, nil
		}
	}
	// Root has MFA and it is not virtual — hardware MFA is in use.
	return nil, nil
}

// checkSupportRoleExists detects whether any IAM role has the AWSSupportAccess
// managed policy attached, which is required to manage incidents with AWS Support.
// IAM.18: Ensure a support role exists to manage incidents with AWS Support.
func (s *IAMScanner) checkSupportRoleExists(ctx context.Context) ([]models.Finding, error) {
	const supportPolicyARN = "arn:aws:iam::aws:policy/AWSSupportAccess"

	paginator := iam.NewListEntitiesForPolicyPaginator(s.client, &iam.ListEntitiesForPolicyInput{
		PolicyArn:    aws.String(supportPolicyARN),
		EntityFilter: types.EntityTypeRole,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if len(page.PolicyRoles) > 0 {
			return nil, nil // at least one role has the policy
		}
	}

	accountARN := fmt.Sprintf("arn:aws:iam::%s:root", s.accountID)
	return []models.Finding{s.newFinding(
		accountARN, "AWS::IAM::Account", "account",
		models.SeverityMedium,
		"No IAM role with AWSSupportAccess policy exists",
		"No IAM role has the AWSSupportAccess managed policy attached. Without a dedicated "+
			"support role, opening AWS Support cases requires using the root account or a "+
			"highly-privileged user, violating least-privilege and making incident response harder.",
		"Create an IAM role (e.g., 'AWSSupportRole') and attach the AWSSupportAccess managed policy. "+
			"Grant only the users or groups that handle AWS Support cases permission to assume this role.",
		"IAM.18",
	)}, nil
}

// checkCredentialsUnused45Days detects IAM user access keys that have not been
// used within the past 45 days (or have never been used on an account older than 45 days).
// IAM.22: IAM user credentials unused for 45 days should be removed.
func (s *IAMScanner) checkCredentialsUnused45Days(ctx context.Context, user types.User) ([]models.Finding, error) {
	const threshold = 45 * 24 * time.Hour
	var findings []models.Finding
	username := aws.ToString(user.UserName)
	userARN := aws.ToString(user.Arn)

	// Skip users created less than 45 days ago — they may not have used keys yet.
	if time.Since(aws.ToTime(user.CreateDate)) <= threshold {
		return nil, nil
	}

	keysOut, err := s.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("listing access keys for %s: %w", username, err)
	}

	for _, key := range keysOut.AccessKeyMetadata {
		if key.Status != types.StatusTypeActive {
			continue
		}
		keyID := aws.ToString(key.AccessKeyId)

		lastUsedOut, err := s.client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
			AccessKeyId: aws.String(keyID),
		})
		if err != nil {
			continue
		}

		var unused bool
		if lastUsedOut.AccessKeyLastUsed == nil || lastUsedOut.AccessKeyLastUsed.LastUsedDate == nil {
			// Key was never used — flag if the key itself is older than 45 days.
			unused = time.Since(aws.ToTime(key.CreateDate)) > threshold
		} else {
			unused = time.Since(aws.ToTime(lastUsedOut.AccessKeyLastUsed.LastUsedDate)) > threshold
		}

		if unused {
			findings = append(findings, s.newFinding(
				userARN, "AWS::IAM::AccessKey", keyID,
				models.SeverityMedium,
				"IAM user access key has not been used in over 45 days",
				fmt.Sprintf(
					"Access key '%s' for user '%s' has not been used in over 45 days. "+
						"Unused credentials that remain active expand the attack surface — "+
						"a compromised key that is never checked can go undetected indefinitely.",
					keyID, username),
				fmt.Sprintf(
					"Deactivate and delete access key '%s' for user '%s' if it is no longer needed. "+
						"If the key is still required, investigate why it has gone unused — this "+
						"may indicate a misconfigured application or a forgotten service account.",
					keyID, username),
				"IAM.22",
			))
		}
	}

	return findings, nil
}

// checkExpiredServerCertificates detects IAM server certificates that have expired.
// IAM.26: Expired SSL/TLS certificates in IAM should be removed.
func (s *IAMScanner) checkExpiredServerCertificates(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding
	now := time.Now().UTC()

	paginator := iam.NewListServerCertificatesPaginator(s.client, &iam.ListServerCertificatesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cert := range page.ServerCertificateMetadataList {
			expiry := aws.ToTime(cert.Expiration)
			if expiry.IsZero() || !now.After(expiry) {
				continue // not expired
			}

			certARN := aws.ToString(cert.Arn)
			certName := aws.ToString(cert.ServerCertificateName)

			findings = append(findings, s.newFinding(
				certARN, "AWS::IAM::ServerCertificate", certName,
				models.SeverityHigh,
				"Expired SSL/TLS certificate found in IAM",
				fmt.Sprintf(
					"Server certificate '%s' expired on %s. Expired certificates stored in IAM "+
						"may be accidentally served by load balancers or applications, causing "+
						"TLS handshake failures or, worse, silent acceptance of expired credentials "+
						"by misconfigured clients.",
					certName, expiry.Format("2006-01-02")),
				fmt.Sprintf(
					"Delete expired certificate '%s' from IAM: "+
						"'aws iam delete-server-certificate --server-certificate-name %s'. "+
						"If the certificate is still in use by a resource, upload a renewed "+
						"certificate first and update the resource to reference the new one before deleting.",
					certName, certName),
				"IAM.26",
			))
		}
	}

	return findings, nil
}

// checkCloudShellFullAccess detects IAM identities with the AWSCloudShellFullAccess
// policy attached.
// IAM.27: IAM identities should not have AWSCloudShellFullAccess attached.
func (s *IAMScanner) checkCloudShellFullAccess(ctx context.Context) ([]models.Finding, error) {
	const cloudShellPolicyARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
	var findings []models.Finding

	paginator := iam.NewListEntitiesForPolicyPaginator(s.client, &iam.ListEntitiesForPolicyInput{
		PolicyArn: aws.String(cloudShellPolicyARN),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, u := range page.PolicyUsers {
			name := aws.ToString(u.UserName)
			arn := fmt.Sprintf("arn:aws:iam::%s:user/%s", s.accountID, name)
			findings = append(findings, s.newFinding(
				arn, "AWS::IAM::User", name,
				models.SeverityMedium,
				"IAM user has AWSCloudShellFullAccess policy attached",
				fmt.Sprintf(
					"User '%s' has AWSCloudShellFullAccess attached. CloudShell provides an "+
						"internet-accessible browser-based shell with pre-configured AWS CLI "+
						"access. Broad assignment can be exploited to exfiltrate credentials, "+
						"enumerate resources, or move laterally using the session's permissions.",
					name),
				fmt.Sprintf(
					"Remove AWSCloudShellFullAccess from user '%s'. If CloudShell access is "+
						"genuinely required, grant it only through an IAM group with a documented "+
						"justification, and scope access via a permission boundary.",
					name),
				"IAM.27",
			))
		}

		for _, g := range page.PolicyGroups {
			name := aws.ToString(g.GroupName)
			arn := fmt.Sprintf("arn:aws:iam::%s:group/%s", s.accountID, name)
			findings = append(findings, s.newFinding(
				arn, "AWS::IAM::Group", name,
				models.SeverityMedium,
				"IAM group has AWSCloudShellFullAccess policy attached",
				fmt.Sprintf(
					"Group '%s' has AWSCloudShellFullAccess attached, granting CloudShell "+
						"access to all members of the group. Any member can use CloudShell "+
						"to exfiltrate credentials or data using the group's permissions.",
					name),
				fmt.Sprintf(
					"Remove AWSCloudShellFullAccess from group '%s'. Audit group members "+
						"who may have been relying on this access and grant CloudShell only "+
						"where explicitly justified.",
					name),
				"IAM.27",
			))
		}

		for _, r := range page.PolicyRoles {
			name := aws.ToString(r.RoleName)
			arn := fmt.Sprintf("arn:aws:iam::%s:role/%s", s.accountID, name)
			findings = append(findings, s.newFinding(
				arn, "AWS::IAM::Role", name,
				models.SeverityMedium,
				"IAM role has AWSCloudShellFullAccess policy attached",
				fmt.Sprintf(
					"Role '%s' has AWSCloudShellFullAccess attached. Any principal that can "+
						"assume this role also inherits CloudShell access, which could be "+
						"exploited for credential exfiltration or lateral movement.",
					name),
				fmt.Sprintf(
					"Remove AWSCloudShellFullAccess from role '%s'. Evaluate whether any "+
						"service or user legitimately requires CloudShell through this role.",
					name),
				"IAM.27",
			))
		}
	}

	return findings, nil
}
