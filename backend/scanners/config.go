package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"

	"cspm-dashboard/backend/models"
)

// ConfigScanner checks whether AWS Config is properly enabled in the region.
// It verifies that a configuration recorder exists, is actively recording,
// covers all resource types, and has a delivery channel configured.
// It implements the Scanner interface.
type ConfigScanner struct {
	client    *configservice.Client
	accountID string
	region    string
}

// NewConfigScanner creates a ConfigScanner from an already-configured AWS SDK config.
func NewConfigScanner(cfg aws.Config, accountID string) *ConfigScanner {
	return &ConfigScanner{
		client:    configservice.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *ConfigScanner) ServiceName() string { return "Config" }

// Scan checks the AWS Config setup for this region: recorder existence,
// recording status, resource coverage, and delivery channel configuration.
func (s *ConfigScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// Fetch recorder configuration and status in parallel logical steps.
	recorders, err := s.client.DescribeConfigurationRecorders(ctx,
		&configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, fmt.Errorf("config: describing recorders: %w", err)
	}

	if len(recorders.ConfigurationRecorders) == 0 {
		// No recorder at all — emit one finding and stop; the remaining checks
		// are all moot when the recorder does not exist.
		findings = append(findings, s.noRecorderFinding())
		return findings, nil
	}

	// Fetch live recording status for the recorder(s) found.
	statusOut, err := s.client.DescribeConfigurationRecorderStatus(ctx,
		&configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		// Non-fatal: continue with other checks.
		statusOut = &configservice.DescribeConfigurationRecorderStatusOutput{}
	}

	statusByName := make(map[string]bool)
	for _, st := range statusOut.ConfigurationRecordersStatus {
		statusByName[aws.ToString(st.Name)] = st.Recording
	}

	for _, rec := range recorders.ConfigurationRecorders {
		name := aws.ToString(rec.Name)

		// Check 1: is the recorder actively recording?
		if recording, ok := statusByName[name]; ok && !recording {
			findings = append(findings, s.recorderNotRecordingFinding(name))
		}

		// Check 2: does the recorder cover all resource types?
		if rec.RecordingGroup != nil && !rec.RecordingGroup.AllSupported {
			findings = append(findings, s.incompleteRecordingGroupFinding(name))
		}
	}

	// Check 3: is a delivery channel configured?
	channels, err := s.client.DescribeDeliveryChannels(ctx,
		&configservice.DescribeDeliveryChannelsInput{})
	if err == nil && len(channels.DeliveryChannels) == 0 {
		findings = append(findings, s.noDeliveryChannelFinding())
	}

	return findings, nil
}

// noRecorderFinding is returned when AWS Config has no configuration recorder
// set up in this region at all.
//
// Why it matters:
// AWS Config is the inventory and change-tracking backbone of an AWS account.
// Without it, there is no continuous record of what resources exist, what they
// look like, and how their configuration has changed over time. It is required
// for many compliance frameworks and is essential for post-incident forensics.
func (s *ConfigScanner) noRecorderFinding() models.Finding {
	resourceID := fmt.Sprintf("arn:aws:config:%s:%s:configuration-recorder/*", s.region, s.accountID)
	return models.Finding{
		ID:           generateID(),
		ResourceID:   resourceID,
		ResourceType: "AWS::Config::ConfigurationRecorder",
		ResourceName: s.region,
		Service:      s.ServiceName(),
		Severity:     models.SeverityHigh,
		Title:        "AWS Config recorder is not enabled in this region",
		Description: fmt.Sprintf(
			"No AWS Config configuration recorder is set up in region %s. "+
				"Config provides a continuous record of resource configurations and "+
				"change history. Without it, there is no way to audit what resources "+
				"existed at a given point in time, detect configuration drift, or "+
				"investigate what changed before an incident.",
			s.region),
		Recommendation: "Enable AWS Config in this region: create a configuration recorder " +
			"that captures all resource types, set up an S3 delivery bucket, and " +
			"optionally configure a delivery channel to SNS for change notifications. " +
			"Consider enabling Config organisation-wide via AWS Organizations.",
		CISControl:           "3.5",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// recorderNotRecordingFinding is returned when a recorder exists but is stopped.
func (s *ConfigScanner) recorderNotRecordingFinding(recorderName string) models.Finding {
	resourceID := fmt.Sprintf("arn:aws:config:%s:%s:configuration-recorder/%s",
		s.region, s.accountID, recorderName)
	return models.Finding{
		ID:           generateID(),
		ResourceID:   resourceID,
		ResourceType: "AWS::Config::ConfigurationRecorder",
		ResourceName: recorderName,
		Service:      s.ServiceName(),
		Severity:     models.SeverityHigh,
		Title:        "AWS Config recorder exists but is not recording",
		Description: fmt.Sprintf(
			"Configuration recorder '%s' exists in region %s but is not currently "+
				"recording. Resource configuration changes since recording was stopped "+
				"are not captured, creating a gap in the audit trail and compliance evidence.",
			recorderName, s.region),
		Recommendation: fmt.Sprintf(
			"Start the recorder: 'aws configservice start-configuration-recorder "+
				"--configuration-recorder-name %s'. Investigate why it was stopped — "+
				"if not intentional, treat as a potential security incident.",
			recorderName),
		CISControl:           "3.5",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// incompleteRecordingGroupFinding is returned when the recorder does not
// cover all supported resource types.
func (s *ConfigScanner) incompleteRecordingGroupFinding(recorderName string) models.Finding {
	resourceID := fmt.Sprintf("arn:aws:config:%s:%s:configuration-recorder/%s",
		s.region, s.accountID, recorderName)
	return models.Finding{
		ID:           generateID(),
		ResourceID:   resourceID,
		ResourceType: "AWS::Config::ConfigurationRecorder",
		ResourceName: recorderName,
		Service:      s.ServiceName(),
		Severity:     models.SeverityMedium,
		Title:        "AWS Config recorder is not recording all resource types",
		Description: fmt.Sprintf(
			"Configuration recorder '%s' is configured with AllSupported=false, "+
				"meaning only a subset of resource types are being tracked. "+
				"Resources outside that subset will not appear in Config's inventory "+
				"and their changes will not be auditable.",
			recorderName),
		Recommendation: fmt.Sprintf(
			"Update recorder '%s' to set AllSupported=true so all current and "+
				"future resource types are automatically tracked. Also enable "+
				"IncludeGlobalResourceTypes to capture IAM resources.",
			recorderName),
		CISControl:           "3.5",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}

// noDeliveryChannelFinding is returned when there is no delivery channel to
// send Config snapshots and change notifications to an S3 bucket.
func (s *ConfigScanner) noDeliveryChannelFinding() models.Finding {
	resourceID := fmt.Sprintf("arn:aws:config:%s:%s:delivery-channel/*", s.region, s.accountID)
	return models.Finding{
		ID:           generateID(),
		ResourceID:   resourceID,
		ResourceType: "AWS::Config::DeliveryChannel",
		ResourceName: s.region,
		Service:      s.ServiceName(),
		Severity:     models.SeverityHigh,
		Title:        "AWS Config delivery channel is not configured",
		Description: fmt.Sprintf(
			"No AWS Config delivery channel is configured in region %s. Without one, "+
				"Config cannot deliver configuration snapshots, history files, or "+
				"compliance notifications to an S3 bucket or SNS topic. "+
				"Configuration data is not persisted beyond the Config service itself.",
			s.region),
		Recommendation: "Create a delivery channel that points to a dedicated S3 bucket " +
			"for long-term storage of Config snapshots and history. Optionally configure " +
			"an SNS topic for real-time notifications on configuration changes.",
		CISControl:           "3.5",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "NIST"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}
