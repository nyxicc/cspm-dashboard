package scanners

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"cspm-dashboard/backend/models"
)

// SecurityHubScanner checks whether AWS Security Hub is enabled in the region
// and whether any critical findings have remained unresolved for 30+ days.
// It implements the Scanner interface.
type SecurityHubScanner struct {
	client    *securityhub.Client
	accountID string
	region    string
}

// NewSecurityHubScanner creates a SecurityHubScanner from an already-configured
// AWS SDK config.
func NewSecurityHubScanner(cfg aws.Config, accountID string) *SecurityHubScanner {
	return &SecurityHubScanner{
		client:    securityhub.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *SecurityHubScanner) ServiceName() string { return "SecurityHub" }

// Scan checks Security Hub enrollment status and then, if it is active, looks
// for critical findings that have been open for more than 30 days.
func (s *SecurityHubScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// DescribeHub returns basic hub information when Security Hub is subscribed.
	// If it is not subscribed, it returns an InvalidAccessException.
	hubOut, err := s.client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		var invalidAccess *shtypes.InvalidAccessException
		if errors.As(err, &invalidAccess) {
			findings = append(findings, s.notEnabledFinding())
			return findings, nil
		}
		// Other errors (throttling, permissions) — bubble up.
		return nil, fmt.Errorf("securityhub: describing hub: %w", err)
	}

	// Hub is active — check for stale critical findings.
	hubARN := aws.ToString(hubOut.HubArn)
	if fs := s.checkOldCriticalFindings(ctx, hubARN); fs != nil {
		findings = append(findings, *fs)
	}

	return findings, nil
}

// notEnabledFinding returns a High finding when Security Hub is not subscribed.
//
// Why it matters:
// Security Hub aggregates findings from GuardDuty, Inspector, Macie, Config,
// IAM Access Analyzer, and dozens of third-party tools into a single pane.
// Without it, security signals are fragmented across services with no unified
// view, no cross-service correlation, and no centralised compliance score.
// CIS, PCI-DSS, and other standards offer automated checks only through Hub.
func (s *SecurityHubScanner) notEnabledFinding() models.Finding {
	return models.Finding{
		ID:           generateID(),
		ResourceID:   fmt.Sprintf("arn:aws:securityhub:%s:%s:hub/default", s.region, s.accountID),
		ResourceType: "AWS::SecurityHub::Hub",
		ResourceName: s.region,
		Service:      s.ServiceName(),
		Severity:     models.SeverityHigh,
		Title:        "AWS Security Hub is not enabled in this region",
		Description: fmt.Sprintf(
			"Security Hub is not subscribed in region %s. Security Hub provides a "+
				"centralised view of security findings from GuardDuty, Inspector, Macie, "+
				"Config, and third-party tools. Without it, there is no unified security "+
				"posture dashboard, no cross-service finding correlation, and no automated "+
				"compliance checks against CIS, PCI-DSS, or NIST standards.",
			s.region),
		Recommendation: "Enable Security Hub in this region via the console or CLI: " +
			"'aws securityhub enable-security-hub --enable-default-standards'. " +
			"Enable the CIS AWS Foundations Benchmark and AWS Foundational Security " +
			"Best Practices standards. Consider enabling Hub organisation-wide using " +
			"AWS Organizations delegated administration.",
		CISControl:           "",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// checkOldCriticalFindings queries Security Hub for CRITICAL severity findings
// that are still active and unresolved and were created more than 30 days ago.
// Returns a single summary finding if any are found, nil otherwise.
//
// Why it matters:
// A critical finding that remains open for 30+ days indicates a gap in the
// security remediation process. Either the finding has been missed, deemed
// acceptable without documentation, or the responsible team lacks the
// capacity to address it. Unresolved critical findings dramatically increase
// the probability and impact of a security incident.
func (s *SecurityHubScanner) checkOldCriticalFindings(ctx context.Context, hubARN string) *models.Finding {
	thirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)

	// Filter for: CRITICAL severity, ACTIVE record state, NEW workflow (unresolved),
	// and created before the 30-day threshold.
	out, err := s.client.GetFindings(ctx, &securityhub.GetFindingsInput{
		Filters: &shtypes.AwsSecurityFindingFilters{
			SeverityLabel: []shtypes.StringFilter{
				{
					Value:      aws.String("CRITICAL"),
					Comparison: shtypes.StringFilterComparisonEquals,
				},
			},
			RecordState: []shtypes.StringFilter{
				{
					Value:      aws.String("ACTIVE"),
					Comparison: shtypes.StringFilterComparisonEquals,
				},
			},
			WorkflowStatus: []shtypes.StringFilter{
				{
					Value:      aws.String("NEW"),
					Comparison: shtypes.StringFilterComparisonEquals,
				},
			},
			CreatedAt: []shtypes.DateFilter{
				{
					// End = 30 days ago means "created before this date" = older than 30 days.
					End: aws.String(thirtyDaysAgo),
				},
			},
		},
		MaxResults: aws.Int32(100),
	})
	if err != nil {
		// If we can't query findings, skip this check rather than surfacing an error.
		return nil
	}

	count := len(out.Findings)
	if count == 0 {
		return nil
	}

	return &models.Finding{
		ID:           generateID(),
		ResourceID:   hubARN,
		ResourceType: "AWS::SecurityHub::Hub",
		ResourceName: "SecurityHub",
		Service:      s.ServiceName(),
		Severity:     models.SeverityHigh,
		Title:        fmt.Sprintf("Security Hub has %d critical finding(s) unresolved for 30+ days", count),
		Description: fmt.Sprintf(
			"%d critical Security Hub finding(s) have been open and unresolved for more "+
				"than 30 days. Unresolved critical findings represent known, high-impact "+
				"risks that have not been mitigated. The longer a critical finding remains "+
				"open, the greater the window of exposure to exploitation.",
			count),
		Recommendation: "Review the critical findings in Security Hub and triage each one. " +
			"For each finding: remediate the underlying issue and set workflow status to " +
			"RESOLVED, or document a risk acceptance decision and set status to SUPPRESSED " +
			"with a justification note. Consider enabling automated response rules for " +
			"common critical finding types.",
		CISControl:           "",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}
