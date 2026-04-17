package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"cspm-dashboard/backend/models"
)

// BlobStorageScanner checks Azure Storage accounts for security misconfigurations
// including public blob access, HTTPS enforcement, encryption, and minimum TLS
// version. It is the Azure equivalent of the AWS S3 scanner.
type BlobStorageScanner struct {
	client         *armstorage.AccountsClient
	subscriptionID string
}

// NewBlobStorageScanner creates a BlobStorageScanner from an Azure credential.
func NewBlobStorageScanner(cred *azidentity.ClientSecretCredential, subscriptionID string) *BlobStorageScanner {
	client, _ := armstorage.NewAccountsClient(subscriptionID, cred, nil)
	return &BlobStorageScanner{client: client, subscriptionID: subscriptionID}
}

// ServiceName satisfies the Scanner interface.
func (s *BlobStorageScanner) ServiceName() string { return "BlobStorage" }

// Scan paginates over all Storage accounts in the subscription and runs per-account checks.
func (s *BlobStorageScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	pager := s.client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("blobstorage: listing accounts: %w", err)
		}

		for _, account := range page.Value {
			if account.Properties == nil {
				continue
			}
			name := strVal(account.Name)
			id := strVal(account.ID)
			location := strVal(account.Location)
			resourceType := "Microsoft.Storage/storageAccounts"

			if f := s.checkPublicAccess(account, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkHTTPSOnly(account, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkMinimumTLS(account, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkEncryption(account, id, name, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings, nil
}

// checkPublicAccess detects storage accounts that allow public blob access.
// Public blob access enables anonymous reads of blob containers and their
// contents without any authentication.
func (s *BlobStorageScanner) checkPublicAccess(account *armstorage.Account, id, name, resourceType, location string) *models.Finding {
	// AllowBlobPublicAccess == nil means the default (allowed in older accounts)
	if account.Properties.AllowBlobPublicAccess != nil && !*account.Properties.AllowBlobPublicAccess {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		"Storage account allows public blob access",
		fmt.Sprintf("Storage account '%s' has AllowBlobPublicAccess enabled or unset. "+
			"Individual containers within this account can be configured for anonymous "+
			"read access, potentially exposing sensitive files to the public internet "+
			"without requiring authentication.", name),
		fmt.Sprintf("Disable public blob access on storage account '%s': "+
			"az storage account update --name %s --allow-blob-public-access false. "+
			"This is a prerequisite to prevent any container within the account "+
			"from being made publicly accessible.", name, name),
		"CIS Azure 3.5",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
	)
	return &f
}

// checkHTTPSOnly detects storage accounts that allow unencrypted HTTP connections.
func (s *BlobStorageScanner) checkHTTPSOnly(account *armstorage.Account, id, name, resourceType, location string) *models.Finding {
	if boolVal(account.Properties.EnableHTTPSTrafficOnly) {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		"Storage account permits unencrypted HTTP connections",
		fmt.Sprintf("Storage account '%s' does not enforce HTTPS-only traffic. "+
			"Connections over plain HTTP are allowed, exposing blob data, SAS tokens, "+
			"and credentials to network interception by attackers on the same network "+
			"path (man-in-the-middle attacks).", name),
		fmt.Sprintf("Enable HTTPS-only traffic for storage account '%s': "+
			"az storage account update --name %s --https-only true. "+
			"This immediately rejects any HTTP requests to blobs, tables, queues, and files.", name, name),
		"CIS Azure 3.1",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA", "NIST"},
	)
	return &f
}

// checkMinimumTLS detects storage accounts that accept TLS versions below 1.2.
// TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE, DROWN).
func (s *BlobStorageScanner) checkMinimumTLS(account *armstorage.Account, id, name, resourceType, location string) *models.Finding {
	if account.Properties.MinimumTLSVersion == nil {
		// unset defaults to TLS 1.0 — flag it
	} else if *account.Properties.MinimumTLSVersion == armstorage.MinimumTLSVersionTLS12 {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityMedium,
		"Storage account minimum TLS version is below 1.2",
		fmt.Sprintf("Storage account '%s' accepts TLS connections below version 1.2. "+
			"TLS 1.0 and 1.1 are vulnerable to BEAST, POODLE, and DROWN attacks. "+
			"Clients using these legacy versions may have their data intercepted or "+
			"have sessions hijacked by a network attacker.", name),
		fmt.Sprintf("Set the minimum TLS version to 1.2 for storage account '%s': "+
			"az storage account update --name %s --min-tls-version TLS1_2. "+
			"Verify that all client applications support TLS 1.2 before applying this change.", name, name),
		"CIS Azure 3.15",
		[]string{"CIS", "SOC2", "PCI-DSS"},
	)
	return &f
}

// checkEncryption detects storage accounts where blob service encryption is
// not explicitly enabled. Note: Azure encrypts all storage at rest by default
// since 2017; this check specifically looks for accounts with encryption
// explicitly disabled via older API settings.
func (s *BlobStorageScanner) checkEncryption(account *armstorage.Account, id, name, resourceType, location string) *models.Finding {
	enc := account.Properties.Encryption
	if enc == nil || enc.Services == nil || enc.Services.Blob == nil {
		return nil // cannot determine state, skip
	}
	if boolVal(enc.Services.Blob.Enabled) {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		"Storage account blob service encryption is not enabled",
		fmt.Sprintf("Storage account '%s' has blob service encryption explicitly disabled. "+
			"Data at rest in blob containers is stored unencrypted on Azure infrastructure, "+
			"exposing it to any party with physical or low-level access to the underlying storage.", name),
		fmt.Sprintf("Enable blob encryption for storage account '%s': "+
			"az storage account update --name %s --encryption-services blob. "+
			"Consider enabling customer-managed keys (CMK) via Azure Key Vault for "+
			"additional control over the encryption keys.", name, name),
		"CIS Azure 3.2",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA", "NIST"},
	)
	return &f
}
