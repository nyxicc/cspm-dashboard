// Package azure implements CSPM scanners for Microsoft Azure resources.
// It mirrors the structure of the parent scanners package but targets Azure
// Resource Manager APIs and Microsoft Graph instead of AWS SDK v2.
//
// Authentication uses a Service Principal (client credentials flow):
// the caller supplies tenant_id, client_id, client_secret, and subscription_id.
// Credentials are validated via a lightweight ARM Subscriptions GET before any
// scanning begins — analogous to AWS STS GetCallerIdentity.
package azure

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"cspm-dashboard/backend/models"
	"cspm-dashboard/backend/scanners"
)

// Credentials holds the Azure Service Principal fields needed to authenticate
// against both ARM (Resource Manager) APIs and Microsoft Graph.
type Credentials struct {
	SubscriptionID string
	ClientID       string
	ClientSecret   string
	TenantID       string
}

// BuildScanners authenticates with Azure using the provided Service Principal
// credentials, validates the subscription is accessible, and returns the full
// set of Azure scanners ready to run.
//
// If credential validation fails (wrong secret, expired, subscription not found)
// an error is returned and no scanners are created — callers should surface this
// as HTTP 401.
func BuildScanners(ctx context.Context, creds Credentials) ([]scanners.Scanner, error) {
	azCred, err := azidentity.NewClientSecretCredential(
		creds.TenantID, creds.ClientID, creds.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building credential: %w", err)
	}

	// Validate credentials — equivalent to AWS STS GetCallerIdentity.
	// armsubscriptions.NewClient requires zero special permissions; any valid
	// Service Principal that has at least Reader on the subscription can call it.
	subClient, err := armsubscriptions.NewClient(azCred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building subscriptions client: %w", err)
	}
	resp, err := subClient.Get(ctx, creds.SubscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: invalid credentials or subscription not accessible: %w", err)
	}

	subDisplayName := ""
	if resp.DisplayName != nil {
		subDisplayName = *resp.DisplayName
	}
	log.Printf("[scan] azure subscription: %s (%s) | tenant: %s",
		creds.SubscriptionID, subDisplayName, creds.TenantID)

	return []scanners.Scanner{
		NewKeyVaultScanner(azCred, creds.SubscriptionID),
		NewBlobStorageScanner(azCred, creds.SubscriptionID),
		NewActivityLogScanner(azCred, creds.SubscriptionID),
		NewAzureSQLScanner(azCred, creds.SubscriptionID),
		NewVirtualMachineScanner(azCred, creds.SubscriptionID),
		NewEntraIDScanner(azCred, creds.SubscriptionID, creds.TenantID),
	}, nil
}

// =============================================================================
// Shared helpers
// =============================================================================

// newFinding is the package-level helper used by all Azure scanners to
// construct a Finding with the provider, timestamp, and status pre-populated.
func newFinding(
	resourceID, resourceType, resourceName, service, region, accountID string,
	severity models.Severity,
	title, description, recommendation, cisControl string,
	frameworks []string,
) models.Finding {
	return models.Finding{
		Provider:             "azure",
		ID:                   generateID(),
		ResourceID:           resourceID,
		ResourceType:         resourceType,
		ResourceName:         resourceName,
		Service:              service,
		Severity:             severity,
		Title:                title,
		Description:          description,
		Recommendation:       recommendation,
		CISControl:           cisControl,
		ComplianceFrameworks: frameworks,
		Region:               region,
		AccountID:            accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// generateID returns a cryptographically random hex string used as a finding ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// strVal safely dereferences a *string, returning "" if nil.
func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// boolVal safely dereferences a *bool, returning false if nil.
func boolVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}
