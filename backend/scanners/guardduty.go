package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"cspm-dashboard/backend/models"
)

// GuardDutyScanner checks whether GuardDuty is enabled in the region and
// whether any existing detector is currently active. It implements the
// Scanner interface.
type GuardDutyScanner struct {
	client    *guardduty.Client
	accountID string
	region    string
}

// NewGuardDutyScanner creates a GuardDutyScanner from an already-configured
// AWS SDK config.
func NewGuardDutyScanner(cfg aws.Config, accountID string) *GuardDutyScanner {
	return &GuardDutyScanner{
		client:    guardduty.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *GuardDutyScanner) ServiceName() string { return "GuardDuty" }

// Scan lists all GuardDuty detectors in the region and checks their status.
//
// GuardDuty uses "detectors" as the primary resource — one per region per
// account. ListDetectors returns their IDs; GetDetector returns the status.
// If no detectors exist, the service is not enabled at all.
func (s *GuardDutyScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	listOut, err := s.client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("guardduty: listing detectors: %w", err)
	}

	if len(listOut.DetectorIds) == 0 {
		// GuardDuty has never been enabled in this region.
		findings = append(findings, s.noDetectorFinding())
		return findings, nil
	}

	for _, detectorID := range listOut.DetectorIds {
		det, err := s.client.GetDetector(ctx, &guardduty.GetDetectorInput{
			DetectorId: aws.String(detectorID),
		})
		if err != nil {
			// Skip detectors we cannot inspect rather than aborting the scan.
			continue
		}

		if det.Status == gdtypes.DetectorStatusDisabled {
			findings = append(findings, s.disabledDetectorFinding(detectorID))
		}
	}

	return findings, nil
}

// noDetectorFinding returns a Critical finding when GuardDuty has no
// detectors configured at all in this region.
//
// Why it matters (CIS 3.1 — detective controls):
// GuardDuty uses machine learning, anomaly detection, and threat intelligence
// to continuously monitor CloudTrail events, VPC flow logs, and DNS logs for
// malicious or unauthorised activity. Without it, account takeovers,
// cryptomining, data exfiltration, and reconnaissance go undetected until
// significant damage has already been done.
func (s *GuardDutyScanner) noDetectorFinding() models.Finding {
	return models.Finding{
		ID:           generateID(),
		ResourceID:   fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/*", s.region, s.accountID),
		ResourceType: "AWS::GuardDuty::Detector",
		ResourceName: s.region,
		Service:      s.ServiceName(),
		Severity:     models.SeverityHigh,
		Title:        "GuardDuty is not enabled in this region",
		Description: fmt.Sprintf(
			"Amazon GuardDuty is not configured in region %s. GuardDuty provides "+
				"continuous threat detection by analysing CloudTrail, VPC flow logs, and "+
				"DNS logs. Without it, malicious activity such as compromised credentials, "+
				"cryptomining, data exfiltration, and reconnaissance will go undetected.",
			s.region),
		Recommendation: "Enable GuardDuty in this region via the AWS console or CLI: " +
			"'aws guardduty create-detector --enable'. Consider enabling it in all " +
			"regions simultaneously using AWS Organizations delegated administration. " +
			"Review GuardDuty findings regularly and integrate with Security Hub.",
		CISControl:           "",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// disabledDetectorFinding returns a Critical finding when a GuardDuty
// detector exists but has been disabled.
//
// Why it matters:
// A detector that was previously active and is now disabled is a significant
// red flag — it may indicate that an attacker deliberately disabled threat
// detection to operate without triggering alerts before taking further action.
// Even if the reason is benign (e.g., cost saving), the protection gap must
// be treated as a critical control failure.
func (s *GuardDutyScanner) disabledDetectorFinding(detectorID string) models.Finding {
	arn := fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/%s", s.region, s.accountID, detectorID)
	return models.Finding{
		ID:           generateID(),
		ResourceID:   arn,
		ResourceType: "AWS::GuardDuty::Detector",
		ResourceName: detectorID,
		Service:      s.ServiceName(),
		Severity:     models.SeverityCritical,
		Title:        "GuardDuty detector exists but is disabled",
		Description: fmt.Sprintf(
			"GuardDuty detector '%s' in region %s is present but has been disabled. "+
				"No threat detection is occurring. Disabling an existing detector is "+
				"a common attacker tactic to eliminate monitoring before escalating "+
				"privileges or exfiltrating data.",
			detectorID, s.region),
		Recommendation: fmt.Sprintf(
			"Re-enable detector '%s' immediately: 'aws guardduty update-detector "+
				"--detector-id %s --enable'. Investigate the CloudTrail event that "+
				"disabled it — if it was not authorised, treat this as a potential "+
				"security incident and begin an investigation.",
			detectorID, detectorID),
		CISControl:           "",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}
