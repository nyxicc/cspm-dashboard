package scanners

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"cspm-dashboard/backend/models"
)

// sensitiveEnvPatterns is the list of substrings that, when found in an
// environment variable NAME (uppercased), suggest the variable holds a secret.
// We check names only — not values — to avoid inadvertently reading secrets.
var sensitiveEnvPatterns = []string{
	"PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY",
	"TOKEN", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIALS",
	"AUTH_TOKEN", "APP_KEY", "APP_SECRET",
}

// LambdaScanner checks every Lambda function in the region for common security
// misconfigurations: overly permissive execution roles, missing VPC placement,
// and environment variables whose names suggest they contain secrets.
// It implements the Scanner interface.
type LambdaScanner struct {
	lambdaClient *lambda.Client
	iamClient    *iamsvc.Client
	accountID    string
	region       string
}

// NewLambdaScanner creates a LambdaScanner from an already-configured AWS SDK
// config. Both a Lambda client and an IAM client are needed because the role
// check requires IAM API calls against the execution role ARN returned by Lambda.
func NewLambdaScanner(cfg aws.Config, accountID string) *LambdaScanner {
	return &LambdaScanner{
		lambdaClient: lambda.NewFromConfig(cfg),
		iamClient:    iamsvc.NewFromConfig(cfg),
		accountID:    accountID,
		region:       cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *LambdaScanner) ServiceName() string { return "Lambda" }

// Scan paginates over every Lambda function in the region and runs three
// security checks against each one. Errors on individual functions are
// skipped to keep the scan resilient.
func (s *LambdaScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("lambda: listing functions: %w", err)
		}

		for _, fn := range page.Functions {
			if f := s.checkLambdaVPC(fn); f != nil {
				findings = append(findings, *f)
			}
			if fs := s.checkLambdaEnvSecrets(fn); len(fs) > 0 {
				findings = append(findings, fs...)
			}
			// Role check makes additional IAM API calls — skip on error.
			if fs, err := s.checkLambdaAdminRole(ctx, fn); err == nil {
				findings = append(findings, fs...)
			}
		}
	}

	return findings, nil
}

// checkLambdaVPC detects Lambda functions that are not deployed inside a VPC.
//
// Why it matters:
// Lambda functions outside a VPC run in AWS-managed network space and cannot
// access private resources (RDS, ElastiCache, internal services) without
// public endpoints or VPC peering. More importantly, a function outside a VPC
// cannot be protected by VPC security groups, NACLs, or VPC flow logs. Any
// outbound connection the function makes — including to exfiltration endpoints
// — is not captured or controllable through network controls.
func (s *LambdaScanner) checkLambdaVPC(fn lambdatypes.FunctionConfiguration) *models.Finding {
	name := aws.ToString(fn.FunctionName)
	arn := aws.ToString(fn.FunctionArn)

	inVPC := fn.VpcConfig != nil && aws.ToString(fn.VpcConfig.VpcId) != ""
	if inVPC {
		return nil
	}

	return s.newFinding(arn, name,
		models.SeverityMedium,
		"Lambda function is not deployed inside a VPC",
		fmt.Sprintf(
			"Function '%s' runs outside a VPC. It cannot be protected by VPC security "+
				"groups or NACLs, its network traffic is not captured by VPC flow logs, "+
				"and it cannot access private resources without exposing them to the internet.",
			name),
		fmt.Sprintf(
			"Configure function '%s' to run inside a VPC by specifying a VPC, subnets, "+
				"and a security group. Use private subnets for functions that do not need "+
				"direct internet access, and attach a NAT gateway for outbound-only internet "+
				"connectivity. Ensure the security group follows least-privilege rules.",
			name),
		"",
	)
}

// checkLambdaEnvSecrets detects environment variables whose NAMES match
// patterns associated with sensitive credentials (passwords, tokens, keys).
//
// Why it matters:
// Hardcoding secrets in Lambda environment variables is a common shortcut
// that introduces significant risk: the values are visible in the AWS console,
// CLI output, CloudFormation templates, and any infrastructure-as-code
// repository. They are also often included in log output by accident.
// Secrets should be stored in AWS Secrets Manager or SSM Parameter Store
// and retrieved at runtime via the SDK.
//
// Note: we check variable NAMES only, not values, to avoid inadvertently
// processing actual secret material during the scan.
func (s *LambdaScanner) checkLambdaEnvSecrets(fn lambdatypes.FunctionConfiguration) []models.Finding {
	name := aws.ToString(fn.FunctionName)
	arn := aws.ToString(fn.FunctionArn)

	if fn.Environment == nil || len(fn.Environment.Variables) == 0 {
		return nil
	}

	var findings []models.Finding
	for varName := range fn.Environment.Variables {
		upper := strings.ToUpper(varName)
		for _, pattern := range sensitiveEnvPatterns {
			if strings.Contains(upper, pattern) {
				findings = append(findings, *s.newFinding(arn, name,
					models.SeverityCritical,
					fmt.Sprintf("Lambda function environment variable '%s' may contain a secret", varName),
					fmt.Sprintf(
						"Function '%s' has an environment variable named '%s' whose name "+
							"suggests it holds a sensitive credential. Environment variables are "+
							"visible in the AWS console, CLI output, IaC templates, and can leak "+
							"into logs. If this variable holds a real secret it is at risk of "+
							"exposure.",
						name, varName),
					fmt.Sprintf(
						"Move the secret value for '%s' in function '%s' to AWS Secrets Manager "+
							"or SSM Parameter Store. Update the function to retrieve the secret "+
							"at runtime using the SDK. Remove the environment variable from the "+
							"Lambda configuration once migrated.",
						varName, name),
					"",
				))
				break // one finding per variable, avoid duplicate patterns
			}
		}
	}
	return findings
}

// checkLambdaAdminRole detects Lambda functions whose execution role has
// AdministratorAccess attached — either as a managed policy or an inline policy.
//
// Why it matters:
// A Lambda function with AdministratorAccess can call any AWS API on behalf
// of the account. If the function is compromised (via a dependency confusion
// attack, code injection, or SSRF), an attacker can use it to escalate to
// full account control. Execution roles should follow least privilege —
// granting only the specific actions and resources the function needs.
func (s *LambdaScanner) checkLambdaAdminRole(ctx context.Context, fn lambdatypes.FunctionConfiguration) ([]models.Finding, error) {
	fnName := aws.ToString(fn.FunctionName)
	fnARN := aws.ToString(fn.FunctionArn)
	roleARN := aws.ToString(fn.Role)

	if roleARN == "" {
		return nil, nil
	}

	// Extract the role name from the ARN: arn:aws:iam::123:role/my-role → my-role
	parts := strings.Split(roleARN, "/")
	roleName := parts[len(parts)-1]

	// Check attached managed policies.
	attachedOut, err := s.iamClient.ListAttachedRolePolicies(ctx,
		&iamsvc.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, fmt.Errorf("listing attached policies for role %s: %w", roleName, err)
	}
	for _, p := range attachedOut.AttachedPolicies {
		if aws.ToString(p.PolicyArn) == adminPolicyARN {
			return []models.Finding{*s.newFinding(fnARN, fnName,
				models.SeverityCritical,
				"Lambda function execution role has AdministratorAccess",
				fmt.Sprintf(
					"Function '%s' uses execution role '%s' which has the AWS-managed "+
						"AdministratorAccess policy attached. If the function is compromised, "+
						"an attacker gains unrestricted access to every service and resource "+
						"in the account.",
					fnName, roleName),
				fmt.Sprintf(
					"Replace AdministratorAccess on role '%s' with a least-privilege policy "+
						"that grants only the specific actions and resources function '%s' requires. "+
						"Use IAM Access Analyzer to generate a policy based on actual access patterns.",
					roleName, fnName),
				"",
			)}, nil
		}
	}

	// Check inline policies embedded directly in the role.
	inlineOut, err := s.iamClient.ListRolePolicies(ctx,
		&iamsvc.ListRolePoliciesInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, fmt.Errorf("listing inline policies for role %s: %w", roleName, err)
	}
	for _, policyName := range inlineOut.PolicyNames {
		pOut, err := s.iamClient.GetRolePolicy(ctx, &iamsvc.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			continue
		}
		doc, err := url.QueryUnescape(aws.ToString(pOut.PolicyDocument))
		if err != nil {
			continue
		}
		if isAdminPolicy(doc) {
			return []models.Finding{*s.newFinding(fnARN, fnName,
				models.SeverityCritical,
				"Lambda function execution role has inline admin policy",
				fmt.Sprintf(
					"Function '%s' uses execution role '%s' which has an inline policy "+
						"named '%s' that grants Effect:Allow on Action:* and Resource:*. "+
						"This is functionally equivalent to AdministratorAccess.",
					fnName, roleName, policyName),
				fmt.Sprintf(
					"Delete inline policy '%s' from role '%s' and replace it with a scoped "+
						"policy granting only the permissions function '%s' actually needs.",
					policyName, roleName, fnName),
				"",
			)}, nil
		}
	}

	return nil, nil
}

// newFinding constructs a Lambda finding with all shared fields populated.
func (s *LambdaScanner) newFinding(
	resourceID, resourceName string,
	severity models.Severity,
	title, description, recommendation, cisControl string,
) *models.Finding {
	return &models.Finding{
		ID:                   generateID(),
		ResourceID:           resourceID,
		ResourceType:         "AWS::Lambda::Function",
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

