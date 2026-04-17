package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"

	"cspm-dashboard/backend/models"
)

// KeyVaultScanner checks Azure Key Vaults for security misconfigurations
// including missing soft delete, missing purge protection, public network
// access, and absence of RBAC authorization. It implements the Scanner interface.
type KeyVaultScanner struct {
	client         *armkeyvault.VaultsClient
	subscriptionID string
}

// NewKeyVaultScanner creates a KeyVaultScanner from an Azure credential.
func NewKeyVaultScanner(cred *azidentity.ClientSecretCredential, subscriptionID string) *KeyVaultScanner {
	client, _ := armkeyvault.NewVaultsClient(subscriptionID, cred, nil)
	return &KeyVaultScanner{client: client, subscriptionID: subscriptionID}
}

// ServiceName satisfies the Scanner interface.
func (s *KeyVaultScanner) ServiceName() string { return "KeyVault" }

// Scan paginates over all Key Vaults in the subscription and runs per-vault checks.
func (s *KeyVaultScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	pager := s.client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("keyvault: listing vaults: %w", err)
		}

		for _, vault := range page.Value {
			if vault.Properties == nil {
				continue
			}
			name := strVal(vault.Name)
			id := strVal(vault.ID)
			location := strVal(vault.Location)
			resourceType := "Microsoft.KeyVault/vaults"

			if f := s.checkSoftDelete(vault, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkPurgeProtection(vault, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkPublicAccess(vault, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkRBACAuth(vault, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings, nil
}

// checkSoftDelete detects vaults without soft delete enabled.
// Soft delete retains deleted vaults and secrets for a recovery period,
// protecting against accidental or malicious deletion.
func (s *KeyVaultScanner) checkSoftDelete(vault *armkeyvault.Vault, id, name, resourceType, location string) *models.Finding {
	if boolVal(vault.Properties.EnableSoftDelete) {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		"Key Vault does not have soft delete enabled",
		fmt.Sprintf("Key Vault '%s' does not have soft delete enabled. Without soft delete, "+
			"deleted vaults, keys, secrets, and certificates are immediately purged and "+
			"cannot be recovered. An attacker or accidental deletion could permanently "+
			"destroy cryptographic material and break dependent services.", name),
		fmt.Sprintf("Enable soft delete on Key Vault '%s': "+
			"az keyvault update --name %s --enable-soft-delete true. "+
			"Also configure a retention period (default 90 days) appropriate for your recovery objectives.", name, name),
		"CIS Azure 8.1",
		[]string{"CIS", "SOC2", "PCI-DSS"},
	)
	return &f
}

// checkPurgeProtection detects vaults without purge protection.
// Purge protection prevents permanent deletion of soft-deleted vaults during
// the retention period, guarding against ransomware or insider threats.
func (s *KeyVaultScanner) checkPurgeProtection(vault *armkeyvault.Vault, id, name, resourceType, location string) *models.Finding {
	if boolVal(vault.Properties.EnablePurgeProtection) {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		"Key Vault does not have purge protection enabled",
		fmt.Sprintf("Key Vault '%s' does not have purge protection enabled. Without purge "+
			"protection, a privileged user or attacker who gains access can permanently "+
			"purge deleted keys and secrets even within the soft delete retention window, "+
			"making data recovery impossible.", name),
		fmt.Sprintf("Enable purge protection on Key Vault '%s': "+
			"az keyvault update --name %s --enable-purge-protection true. "+
			"Note: once enabled, purge protection cannot be disabled.", name, name),
		"CIS Azure 8.1",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
	)
	return &f
}

// checkPublicAccess detects vaults that allow public network access when
// private endpoints are expected to be the sole access method.
func (s *KeyVaultScanner) checkPublicAccess(vault *armkeyvault.Vault, id, name, resourceType, location string) *models.Finding {
	props := vault.Properties
	// If NetworkACLs is nil or DefaultAction is not Deny, the vault is publicly accessible
	if props.NetworkACLs != nil &&
		props.NetworkACLs.DefaultAction != nil &&
		*props.NetworkACLs.DefaultAction == armkeyvault.NetworkRuleActionDeny {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityMedium,
		"Key Vault network ACL default action allows public access",
		fmt.Sprintf("Key Vault '%s' network ACL default action is 'Allow', meaning any "+
			"IP address not covered by a Deny rule can reach the vault over the public "+
			"internet. This increases the attack surface for credential stuffing or "+
			"exploitation of any future Key Vault API vulnerabilities.", name),
		fmt.Sprintf("Set the default network ACL action to Deny and configure allowed "+
			"IP ranges or VNet service endpoints for Key Vault '%s': "+
			"az keyvault network-rule add --name %s --default-action Deny. "+
			"Consider using private endpoints for zero-trust access.", name, name),
		"CIS Azure 8.2",
		[]string{"CIS", "SOC2", "PCI-DSS"},
	)
	return &f
}

// checkRBACAuth detects vaults still using the legacy vault access policy model
// instead of Azure RBAC authorization (recommended since 2021).
func (s *KeyVaultScanner) checkRBACAuth(vault *armkeyvault.Vault, id, name, resourceType, location string) *models.Finding {
	if boolVal(vault.Properties.EnableRbacAuthorization) {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityLow,
		"Key Vault uses legacy access policies instead of Azure RBAC",
		fmt.Sprintf("Key Vault '%s' uses vault access policies rather than Azure RBAC. "+
			"Access policies are vault-scoped and cannot be audited or managed via "+
			"Azure Policy, Privileged Identity Management, or standard Azure IAM tooling. "+
			"RBAC provides consistent, auditable, fine-grained access control.", name),
		fmt.Sprintf("Migrate Key Vault '%s' to RBAC authorization: "+
			"az keyvault update --name %s --enable-rbac-authorization true. "+
			"Assign appropriate roles (Key Vault Secrets User, Key Vault Crypto User) "+
			"to principals that previously had access policies.", name, name),
		"",
		[]string{"CIS", "SOC2"},
	)
	return &f
}
