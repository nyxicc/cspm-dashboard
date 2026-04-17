package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armsql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql/v2"

	"cspm-dashboard/backend/models"
)

// AzureSQLScanner checks Azure SQL Server instances and their databases for
// security misconfigurations. It is the Azure equivalent of the AWS RDS scanner.
type AzureSQLScanner struct {
	serversClient  *armsql.ServersClient
	dbClient       *armsql.DatabasesClient
	tdeClient      *armsql.TransparentDataEncryptionsClient
	auditingClient *armsql.ServerBlobAuditingPoliciesClient
	subscriptionID string
}

// NewAzureSQLScanner creates an AzureSQLScanner from an Azure credential.
func NewAzureSQLScanner(cred *azidentity.ClientSecretCredential, subscriptionID string) *AzureSQLScanner {
	serversClient, _ := armsql.NewServersClient(subscriptionID, cred, nil)
	dbClient, _ := armsql.NewDatabasesClient(subscriptionID, cred, nil)
	tdeClient, _ := armsql.NewTransparentDataEncryptionsClient(subscriptionID, cred, nil)
	auditingClient, _ := armsql.NewServerBlobAuditingPoliciesClient(subscriptionID, cred, nil)
	return &AzureSQLScanner{
		serversClient:  serversClient,
		dbClient:       dbClient,
		tdeClient:      tdeClient,
		auditingClient: auditingClient,
		subscriptionID: subscriptionID,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *AzureSQLScanner) ServiceName() string { return "AzureSQL" }

// Scan paginates over all SQL Servers and their databases, running security checks.
func (s *AzureSQLScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	pager := s.serversClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("azuresql: listing servers: %w", err)
		}

		for _, server := range page.Value {
			if server.Properties == nil {
				continue
			}
			serverName := strVal(server.Name)
			serverID := strVal(server.ID)
			location := strVal(server.Location)
			resourceGroup := resourceGroupFromID(serverID)
			resourceType := "Microsoft.Sql/servers"

			if f := s.checkPublicNetworkAccess(server, serverID, serverName, resourceType, location); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkAuditing(ctx, serverID, serverName, resourceType, location, resourceGroup); f != nil {
				findings = append(findings, *f)
			}

			// Per-database checks: TDE
			dbFindings := s.scanDatabases(ctx, serverID, serverName, location, resourceGroup)
			findings = append(findings, dbFindings...)
		}
	}
	return findings, nil
}

// checkPublicNetworkAccess detects SQL Servers that allow connections from
// the public internet.
func (s *AzureSQLScanner) checkPublicNetworkAccess(server *armsql.Server, id, name, resourceType, location string) *models.Finding {
	if server.Properties.PublicNetworkAccess == nil {
		return nil
	}
	if *server.Properties.PublicNetworkAccess == armsql.ServerPublicNetworkAccessFlagDisabled {
		return nil
	}
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		"Azure SQL Server allows public network access",
		fmt.Sprintf("SQL Server '%s' has public network access enabled. The server endpoint "+
			"is reachable from the public internet, increasing the attack surface. "+
			"Brute-force attacks, credential stuffing, and exploitation of SQL Server "+
			"vulnerabilities can be attempted from any IP address.", name),
		fmt.Sprintf("Disable public network access for SQL Server '%s': "+
			"az sql server update --name %s --resource-group <rg> --enable-public-network false. "+
			"Use private endpoints or VNet service endpoints to provide connectivity "+
			"only from trusted networks.", name, name),
		"CIS Azure 4.1",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
	)
	return &f
}

// checkAuditing detects SQL Servers without server-level blob auditing enabled.
func (s *AzureSQLScanner) checkAuditing(ctx context.Context, serverID, serverName, resourceType, location, resourceGroup string) *models.Finding {
	policy, err := s.auditingClient.Get(ctx, resourceGroup, serverName, nil)
	if err != nil {
		return nil // skip on permission error
	}
	if policy.Properties == nil || policy.Properties.State == nil {
		return nil
	}
	if *policy.Properties.State == armsql.BlobAuditingPolicyStateEnabled {
		return nil
	}
	f := newFinding(
		serverID, resourceType, serverName, s.ServiceName(), location, s.subscriptionID,
		models.SeverityMedium,
		"Azure SQL Server auditing is not enabled",
		fmt.Sprintf("SQL Server '%s' does not have server-level auditing enabled. "+
			"Without auditing, database access, query execution, and authentication "+
			"events are not logged. This makes it impossible to detect unauthorized "+
			"access, investigate incidents, or demonstrate compliance.", serverName),
		fmt.Sprintf("Enable auditing for SQL Server '%s': "+
			"az sql server audit-policy update --name %s --resource-group <rg> --state Enabled "+
			"--storage-account <storage-account-name>. "+
			"Configure a retention period of at least 90 days.", serverName, serverName),
		"CIS Azure 4.2",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
	)
	return &f
}

// scanDatabases checks Transparent Data Encryption for each database on the server.
func (s *AzureSQLScanner) scanDatabases(ctx context.Context, serverID, serverName, location, resourceGroup string) []models.Finding {
	var findings []models.Finding

	pager := s.dbClient.NewListByServerPager(resourceGroup, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, db := range page.Value {
			dbName := strVal(db.Name)
			if dbName == "master" {
				continue // master DB is system-managed
			}
			dbID := strVal(db.ID)
			dbLocation := strVal(db.Location)
			if dbLocation == "" {
				dbLocation = location
			}

			if f := s.checkTDE(ctx, dbID, dbName, serverName, dbLocation, resourceGroup); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings
}

// checkTDE detects databases without Transparent Data Encryption enabled.
func (s *AzureSQLScanner) checkTDE(ctx context.Context, dbID, dbName, serverName, location, resourceGroup string) *models.Finding {
	tde, err := s.tdeClient.Get(ctx, resourceGroup, serverName, dbName, "current", nil)
	if err != nil {
		return nil // skip on permission error
	}
	if tde.Properties == nil || tde.Properties.State == nil {
		return nil
	}
	if *tde.Properties.State == armsql.TransparentDataEncryptionStateEnabled {
		return nil
	}
	f := newFinding(
		dbID, "Microsoft.Sql/servers/databases", dbName, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		fmt.Sprintf("Azure SQL database '%s' does not have Transparent Data Encryption enabled", dbName),
		fmt.Sprintf("Database '%s' on SQL Server '%s' has Transparent Data Encryption (TDE) "+
			"disabled. TDE encrypts database files, backups, and transaction logs at rest. "+
			"Without TDE, anyone with access to the underlying storage files can read the "+
			"raw database content without any credentials.", dbName, serverName),
		fmt.Sprintf("Enable TDE for database '%s': "+
			"az sql db tde set --resource-group <rg> --server %s --database %s --status Enabled. "+
			"Consider upgrading to customer-managed keys (BYOK) via Azure Key Vault for "+
			"additional control over the encryption key lifecycle.", dbName, serverName, dbName),
		"CIS Azure 4.5",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
	)
	return &f
}

// resourceGroupFromID parses the resource group name from an Azure ARM resource ID.
// ARM IDs follow the pattern: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
