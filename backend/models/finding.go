// Package models defines the core data structures used throughout the CSPM tool.
package models

import "time"

// Severity represents how critical a security finding is.
// Using a named string type lets the compiler catch cases where a plain string
// is accidentally passed where a Severity is expected.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Status represents the current lifecycle state of a finding.
type Status string

const (
	// StatusOpen means the misconfiguration has been detected and is unresolved.
	StatusOpen Status = "open"
	// StatusResolved means the misconfiguration has been fixed.
	StatusResolved Status = "resolved"
	// StatusSuppressed means the finding has been acknowledged and intentionally
	// accepted as a risk (e.g., a known exception approved by the security team).
	StatusSuppressed Status = "suppressed"
)

// Finding represents a single security misconfiguration detected by a scanner.
// Each Finding maps to one specific issue on one specific cloud resource.
type Finding struct {
	// ID is a unique identifier for this finding (UUID).
	ID string `json:"id"`

	// ResourceID is the cloud provider's identifier for the affected resource,
	// typically an ARN for AWS (e.g., "arn:aws:s3:::my-bucket").
	ResourceID string `json:"resource_id"`

	// ResourceType describes the kind of resource using CloudFormation-style
	// notation (e.g., "AWS::S3::Bucket", "AWS::EC2::SecurityGroup").
	ResourceType string `json:"resource_type"`

	// ResourceName is the human-readable name or Name tag of the resource.
	ResourceName string `json:"resource_name"`

	// Service is the short AWS service name the resource belongs to
	// (e.g., "S3", "EC2", "IAM", "CloudTrail").
	Service string `json:"service"`

	// Severity indicates how critical this finding is to remediate.
	Severity Severity `json:"severity"`

	// Title is a short, one-line summary of the misconfiguration
	// (e.g., "S3 bucket allows public read access").
	Title string `json:"title"`

	// Description explains the misconfiguration in detail: what it is,
	// why it exists, and what an attacker could do by exploiting it.
	Description string `json:"description"`

	// Recommendation provides clear, actionable steps to remediate the finding.
	Recommendation string `json:"recommendation"`

	// CISControl is the CIS Benchmark control identifier this finding maps to
	// (e.g., "2.1.1"). Empty string if the finding has no CIS mapping.
	CISControl string `json:"cis_control,omitempty"`

	// ComplianceFrameworks lists every compliance standard this finding is
	// relevant to (e.g., ["CIS", "SOC2", "PCI-DSS", "NIST", "HIPAA"]).
	ComplianceFrameworks []string `json:"compliance_frameworks,omitempty"`

	// Region is the AWS region where the affected resource lives
	// (e.g., "us-east-1"). Use "global" for region-independent resources like IAM.
	Region string `json:"region"`

	// AccountID is the 12-digit AWS account ID that owns the resource.
	AccountID string `json:"account_id"`

	// Status tracks whether this finding is open, resolved, or suppressed.
	Status Status `json:"status"`

	// Timestamp is when this finding was first detected by the scanner.
	Timestamp time.Time `json:"timestamp"`
}
