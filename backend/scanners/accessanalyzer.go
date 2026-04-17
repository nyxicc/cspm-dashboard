package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"

	"cspm-dashboard/backend/models"
)

// AccessAnalyzerScanner checks whether IAM Access Analyzer is enabled in the
// region with at least one active analyzer. It implements the Scanner interface.
type AccessAnalyzerScanner struct {
	client    *accessanalyzer.Client
	accountID string
	region    string
}

// NewAccessAnalyzerScanner creates an AccessAnalyzerScanner from an already-configured
// AWS SDK config.
func NewAccessAnalyzerScanner(cfg aws.Config, accountID string) *AccessAnalyzerScanner {
	return &AccessAnalyzerScanner{
		client:    accessanalyzer.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *AccessAnalyzerScanner) ServiceName() string { return "AccessAnalyzer" }

// Scan checks whether at least one active IAM Access Analyzer exists in the region.
//
// Why it matters (IAM.28):
// IAM Access Analyzer continuously monitors resource policies (S3 buckets, IAM roles,
// KMS keys, Lambda functions, SQS queues, Secrets Manager secrets) and alerts when
// they grant access to external principals. Without it, resources accidentally made
// public or shared with unintended accounts go undetected until exploited.
func (s *AccessAnalyzerScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	out, err := s.client.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		return nil, fmt.Errorf("accessanalyzer: listing analyzers: %w", err)
	}

	for _, analyzer := range out.Analyzers {
		if analyzer.Status == aatypes.AnalyzerStatusActive {
			return nil, nil // at least one active analyzer — control passes
		}
	}

	resourceID := fmt.Sprintf("arn:aws:access-analyzer:%s:%s:analyzer/*", s.region, s.accountID)
	return []models.Finding{{
		ID:           generateID(),
		ResourceID:   resourceID,
		ResourceType: "AWS::AccessAnalyzer::Analyzer",
		ResourceName: s.region,
		Service:      s.ServiceName(),
		Severity:     models.SeverityMedium,
		Title:        "IAM Access Analyzer is not enabled in this region",
		Description: fmt.Sprintf(
			"No active IAM Access Analyzer is configured in region %s. "+
				"Without it, there is no automated detection of resource policies that "+
				"grant unintended access to external principals (other AWS accounts, "+
				"federated users, or the public internet). Overly permissive policies "+
				"on S3, IAM roles, KMS keys, and other resources go undetected.",
			s.region),
		Recommendation: "Enable IAM Access Analyzer in this region: in the IAM console, " +
			"navigate to Access Analyzer and create a new analyzer with type 'Account'. " +
			"Review all existing findings and resolve unintended external access. " +
			"Consider creating an Organization-level analyzer for cross-account visibility.",
		CISControl:           "IAM.28",
		ComplianceFrameworks: []string{"CIS", "AWS-FSBP", "SOC2"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}}, nil
}
