package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"cspm-dashboard/backend/models"
)

// ActivityLogScanner checks Azure Monitor diagnostic settings and activity log
// alert rules for the subscription. It is the Azure equivalent of the AWS
// CloudTrail scanner.
type ActivityLogScanner struct {
	diagClient    *armmonitor.DiagnosticSettingsClient
	alertsClient  *armmonitor.ActivityLogAlertsClient
	subscriptionID string
}

// NewActivityLogScanner creates an ActivityLogScanner from an Azure credential.
func NewActivityLogScanner(cred *azidentity.ClientSecretCredential, subscriptionID string) *ActivityLogScanner {
	diagClient, _ := armmonitor.NewDiagnosticSettingsClient(cred, nil)
	alertsClient, _ := armmonitor.NewActivityLogAlertsClient(subscriptionID, cred, nil)
	return &ActivityLogScanner{
		diagClient:     diagClient,
		alertsClient:   alertsClient,
		subscriptionID: subscriptionID,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *ActivityLogScanner) ServiceName() string { return "ActivityLog" }

// Scan checks subscription-level activity log diagnostic settings and alert rules.
func (s *ActivityLogScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// Subscription-level diagnostic settings resource URI
	resourceURI := fmt.Sprintf("/subscriptions/%s", s.subscriptionID)
	resourceType := "Microsoft.Subscription"
	resourceName := s.subscriptionID

	diagSettings, err := s.listDiagnosticSettings(ctx, resourceURI)
	if err != nil {
		return findings, fmt.Errorf("activitylog: listing diagnostic settings: %w", err)
	}

	if f := s.checkDiagnosticSettingsExist(diagSettings, resourceURI, resourceName, resourceType); f != nil {
		findings = append(findings, *f)
	} else {
		// Only check retention if settings exist
		if f := s.checkLogRetention(diagSettings, resourceURI, resourceName, resourceType); f != nil {
			findings = append(findings, *f)
		}
	}

	alerts, err := s.listAlertRules(ctx)
	if err != nil {
		// Non-fatal: alert rules check is best-effort
		return findings, nil
	}

	if f := s.checkAlertRulesExist(alerts, resourceURI, resourceName, resourceType); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

func (s *ActivityLogScanner) listDiagnosticSettings(ctx context.Context, resourceURI string) ([]*armmonitor.DiagnosticSettingsResource, error) {
	var settings []*armmonitor.DiagnosticSettingsResource
	pager := s.diagClient.NewListPager(resourceURI, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		settings = append(settings, page.Value...)
	}
	return settings, nil
}

func (s *ActivityLogScanner) listAlertRules(ctx context.Context) ([]*armmonitor.ActivityLogAlertResource, error) {
	var alerts []*armmonitor.ActivityLogAlertResource
	pager := s.alertsClient.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, page.Value...)
	}
	return alerts, nil
}

// checkDiagnosticSettingsExist detects subscriptions with no diagnostic settings
// configured to export the Azure Activity Log. Without this, administrative
// operations (resource creation, deletion, role changes) are not captured in
// a durable log store.
func (s *ActivityLogScanner) checkDiagnosticSettingsExist(
	settings []*armmonitor.DiagnosticSettingsResource,
	resourceID, resourceName, resourceType string,
) *models.Finding {
	// Check if at least one setting has a storage destination or Log Analytics workspace
	for _, setting := range settings {
		if setting.Properties == nil {
			continue
		}
		if setting.Properties.StorageAccountID != nil ||
			setting.Properties.WorkspaceID != nil ||
			setting.Properties.EventHubAuthorizationRuleID != nil {
			return nil // at least one export destination configured
		}
	}

	f := newFinding(
		resourceID, resourceType, resourceName, s.ServiceName(), "global", s.subscriptionID,
		models.SeverityHigh,
		"Subscription has no diagnostic settings exporting the Azure Activity Log",
		"The Azure subscription has no diagnostic settings configured to export "+
			"Activity Log entries to a Storage Account, Log Analytics workspace, or "+
			"Event Hub. Without this, administrative operations — including resource "+
			"creation, deletion, and RBAC changes — are not captured in a durable, "+
			"queryable audit trail.",
		"Create a subscription-level diagnostic setting that exports all Activity Log "+
			"categories to a Log Analytics workspace or Storage Account: "+
			"az monitor diagnostic-settings create --resource /subscriptions/"+s.subscriptionID+
			" --workspace <log-analytics-workspace-id> --logs '[{\"category\":\"Administrative\",\"enabled\":true}]'. "+
			"Retain logs for at least 90 days per CIS and PCI-DSS requirements.",
		"CIS Azure 5.1.1",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA", "NIST"},
	)
	return &f
}

// checkLogRetention detects diagnostic settings with retention periods below
// 90 days, which is the minimum required by CIS and PCI-DSS.
func (s *ActivityLogScanner) checkLogRetention(
	settings []*armmonitor.DiagnosticSettingsResource,
	resourceID, resourceName, resourceType string,
) *models.Finding {
	for _, setting := range settings {
		if setting.Properties == nil {
			continue
		}
		for _, logSetting := range setting.Properties.Logs {
			if logSetting.RetentionPolicy == nil || logSetting.RetentionPolicy.Days == nil {
				continue
			}
			days := *logSetting.RetentionPolicy.Days
			if days > 0 && days < 90 {
				f := newFinding(
					resourceID, resourceType, resourceName, s.ServiceName(), "global", s.subscriptionID,
					models.SeverityMedium,
					fmt.Sprintf("Activity Log retention period is %d days (minimum 90 required)", days),
					fmt.Sprintf("A diagnostic setting has log retention configured for only %d days. "+
						"CIS Azure Benchmark and PCI-DSS require a minimum of 90 days of log retention "+
						"to support incident investigation and forensic analysis. Shorter retention may "+
						"mean logs are deleted before an incident is discovered.", days),
					"Update the log retention policy to at least 90 days: "+
						"az monitor diagnostic-settings update with retentionPolicy.days >= 90. "+
						"For long-term retention consider archiving to Azure Storage with a lifecycle policy.",
					"CIS Azure 5.1.2",
					[]string{"CIS", "SOC2", "PCI-DSS"},
				)
				return &f
			}
		}
	}
	return nil
}

// checkAlertRulesExist detects subscriptions with no Activity Log alert rules.
// Without alert rules, critical events (policy changes, security group changes,
// role assignment changes) go unnoticed until a manual audit.
func (s *ActivityLogScanner) checkAlertRulesExist(
	alerts []*armmonitor.ActivityLogAlertResource,
	resourceID, resourceName, resourceType string,
) *models.Finding {
	if len(alerts) > 0 {
		return nil
	}
	f := newFinding(
		resourceID, resourceType, resourceName, s.ServiceName(), "global", s.subscriptionID,
		models.SeverityMedium,
		"No Activity Log alert rules are configured for this subscription",
		"The subscription has no Activity Log alert rules. Alert rules trigger "+
			"notifications when specific administrative events occur, such as changes "+
			"to security policies, role assignments, firewall rules, or resource deletions. "+
			"Without alerts, a security team cannot detect and respond to suspicious "+
			"activity in near-real time.",
		"Create Activity Log alert rules for high-risk operations: "+
			"az monitor activity-log alert create --name alert-policy-write "+
			"--resource-group <rg> --condition category=Administrative and operationName=Microsoft.Authorization/policyAssignments/write. "+
			"Key operations to alert on: role assignment changes, policy assignment changes, "+
			"network security group modifications, and Key Vault operations.",
		"CIS Azure 5.2",
		[]string{"CIS", "SOC2"},
	)
	return &f
}
