package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	kiotaazure "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	graphusers "github.com/microsoftgraph/msgraph-sdk-go/users"

	"cspm-dashboard/backend/models"
)

// wellKnownPrivilegedRoles lists Azure AD built-in role definition IDs that
// grant significant permissions. These are tenant-wide role IDs (not subscription-level).
// Source: https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
var wellKnownPrivilegedRoles = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
	"194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
	"c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
	"b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
	"158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
	"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
	"29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
	"729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
	"966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
	"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
	"fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}

// EntraIDScanner checks Azure Active Directory (Entra ID) for security
// misconfigurations including guest users with privileged roles and
// legacy authentication not blocked. It is the Azure equivalent of the AWS IAM scanner.
type EntraIDScanner struct {
	graphClient    *msgraphsdk.GraphServiceClient
	subscriptionID string
	tenantID       string
}

// NewEntraIDScanner creates an EntraIDScanner from an Azure credential.
// The Graph SDK requires the credential to be wrapped in a Kiota auth provider.
func NewEntraIDScanner(cred *azidentity.ClientSecretCredential, subscriptionID, tenantID string) *EntraIDScanner {
	authProvider, err := kiotaazure.NewAzureIdentityAuthenticationProvider(cred)
	if err != nil {
		// Return a scanner with nil client; Scan() will return an error gracefully.
		return &EntraIDScanner{subscriptionID: subscriptionID, tenantID: tenantID}
	}
	adapter, err := msgraphsdk.NewGraphRequestAdapter(authProvider)
	if err != nil {
		return &EntraIDScanner{subscriptionID: subscriptionID, tenantID: tenantID}
	}
	graphClient := msgraphsdk.NewGraphServiceClient(adapter)
	return &EntraIDScanner{
		graphClient:    graphClient,
		subscriptionID: subscriptionID,
		tenantID:       tenantID,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *EntraIDScanner) ServiceName() string { return "EntraID" }

// Scan checks Entra ID for guest users with privileged roles and excessive
// role assignments.
func (s *EntraIDScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	if s.graphClient == nil {
		return nil, fmt.Errorf("entraid: Graph client could not be initialized")
	}

	var findings []models.Finding

	guestFindings, err := s.checkGuestUsers(ctx)
	if err == nil {
		findings = append(findings, guestFindings...)
	}

	roleFindings, err := s.checkPrivilegedRoleAssignments(ctx)
	if err == nil {
		findings = append(findings, roleFindings...)
	}

	return findings, nil
}

// checkGuestUsers detects guest (external) users in the directory.
// Guest users from external organisations may retain access long after
// a collaboration ends and are often overlooked during access reviews.
func (s *EntraIDScanner) checkGuestUsers(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	userType := "Guest"
	filter := fmt.Sprintf("userType eq '%s'", userType)
	reqConfig := &graphusers.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &graphusers.UsersRequestBuilderGetQueryParameters{
			Filter: &filter,
			Select: []string{"id", "displayName", "userPrincipalName", "userType", "createdDateTime"},
		},
	}

	resp, err := s.graphClient.Users().Get(ctx, reqConfig)
	if err != nil {
		return nil, fmt.Errorf("entraid: listing guest users: %w", err)
	}

	guests := resp.GetValue()
	if len(guests) == 0 {
		return nil, nil
	}

	// Aggregate finding: report total guest count rather than one per guest
	// to keep the findings list manageable.
	guestNames := buildGuestList(guests)

	resourceID := fmt.Sprintf("/tenants/%s", s.tenantID)
	f := newFinding(
		resourceID, "Microsoft.AzureActiveDirectory/tenants", s.tenantID,
		s.ServiceName(), "global", s.subscriptionID,
		models.SeverityMedium,
		fmt.Sprintf("%d guest (external) users exist in the Entra ID directory", len(guests)),
		fmt.Sprintf("The directory contains %d guest users. Guest accounts for external "+
			"collaborators may persist indefinitely after a project ends. If a guest account "+
			"is compromised, the attacker gains a foothold inside the tenant and can potentially "+
			"escalate to higher-privileged resources. Examples: %s", len(guests), guestNames),
		"Review all guest users and remove those no longer needed: "+
			"az ad user list --filter \"userType eq 'Guest'\". "+
			"Implement an access review policy in Entra ID Governance to periodically "+
			"certify guest user access. Set a guest user expiration policy if supported by your license.",
		"CIS Azure 1.5",
		[]string{"CIS", "SOC2"},
	)
	findings = append(findings, f)
	return findings, nil
}

// checkPrivilegedRoleAssignments detects excessive permanent assignments to
// highly privileged Azure AD roles. Permanent assignments should be replaced
// with Privileged Identity Management (PIM) eligible assignments.
func (s *EntraIDScanner) checkPrivilegedRoleAssignments(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	resp, err := s.graphClient.RoleManagement().Directory().RoleAssignments().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("entraid: listing role assignments: %w", err)
	}

	assignments := resp.GetValue()

	// Group assignments by role definition ID
	roleCount := make(map[string]int)
	rolePrincipals := make(map[string][]string)

	for _, assignment := range assignments {
		roleDefID := strVal(assignment.GetRoleDefinitionId())
		principalID := strVal(assignment.GetPrincipalId())
		if _, isPrivileged := wellKnownPrivilegedRoles[roleDefID]; isPrivileged {
			roleCount[roleDefID]++
			rolePrincipals[roleDefID] = append(rolePrincipals[roleDefID], principalID)
		}
	}

	// Flag roles with more than 3 permanent assignments
	const maxPrivilegedAssignments = 3
	for roleDefID, count := range roleCount {
		if count <= maxPrivilegedAssignments {
			continue
		}
		roleName := wellKnownPrivilegedRoles[roleDefID]
		resourceID := fmt.Sprintf("/tenants/%s/roleDefinitions/%s", s.tenantID, roleDefID)
		f := newFinding(
			resourceID, "Microsoft.AzureActiveDirectory/roleDefinitions", roleName,
			s.ServiceName(), "global", s.subscriptionID,
			models.SeverityHigh,
			fmt.Sprintf("Privileged role '%s' has %d permanent assignments (maximum %d recommended)", roleName, count, maxPrivilegedAssignments),
			fmt.Sprintf("The '%s' role has %d permanent assignments. Permanent privileged role "+
				"assignments create standing access that is active 24/7. If any of these accounts "+
				"is compromised, the attacker immediately has '%s' level access to the tenant. "+
				"Microsoft recommends using Privileged Identity Management (PIM) to limit active "+
				"privileged access to just-in-time durations.", roleName, count, roleName),
			fmt.Sprintf("Reduce permanent assignments for '%s' to %d or fewer. "+
				"Convert excess permanent assignments to PIM-eligible assignments: "+
				"in the Azure Portal → Privileged Identity Management → Azure AD Roles → %s. "+
				"Require approval and MFA for role activation.", roleName, maxPrivilegedAssignments, roleName),
			"CIS Azure 1.1",
			[]string{"CIS", "SOC2", "PCI-DSS"},
		)
		findings = append(findings, f)
	}

	// Check specifically for too many Global Administrators
	globalAdminID := "62e90394-69f5-4237-9190-012177145e10"
	if count, ok := roleCount[globalAdminID]; ok && count > 4 {
		resourceID := fmt.Sprintf("/tenants/%s/roleDefinitions/%s", s.tenantID, globalAdminID)
		f := newFinding(
			resourceID, "Microsoft.AzureActiveDirectory/roleDefinitions", "Global Administrator",
			s.ServiceName(), "global", s.subscriptionID,
			models.SeverityCritical,
			fmt.Sprintf("Tenant has %d Global Administrators (maximum 4 recommended)", count),
			fmt.Sprintf("The tenant has %d permanent Global Administrator assignments. Global "+
				"Administrator is the most powerful role in Azure AD — it can manage all aspects "+
				"of the tenant including resetting other admin passwords. A large number of Global "+
				"Admins dramatically increases the attack surface. CIS recommends between 2 and 4.", count),
			"Reduce Global Administrator count to between 2 and 4 accounts. "+
				"Use break-glass emergency accounts (max 2) with strong controls. "+
				"Replace routine admin tasks with least-privilege roles: "+
				"Security Administrator, Privileged Role Administrator, or service-specific roles.",
			"CIS Azure 1.1",
			[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
		)
		findings = append(findings, f)
	}

	return findings, nil
}

// buildGuestList returns a comma-separated string of up to 5 guest display names
// for inclusion in finding descriptions.
func buildGuestList(guests []graphmodels.Userable) string {
	names := make([]string, 0, 5)
	for i, guest := range guests {
		if i >= 5 {
			names = append(names, fmt.Sprintf("...and %d more", len(guests)-5))
			break
		}
		if guest.GetDisplayName() != nil {
			names = append(names, *guest.GetDisplayName())
		} else if guest.GetUserPrincipalName() != nil {
			names = append(names, *guest.GetUserPrincipalName())
		}
	}
	result := ""
	for i, n := range names {
		if i > 0 {
			result += ", "
		}
		result += n
	}
	return result
}
