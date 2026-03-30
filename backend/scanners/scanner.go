// Package scanners defines the Scanner interface that every AWS service scanner
// must implement, along with shared types used when running scans.
package scanners

import (
	"context"

	"cspm-dashboard/backend/models"
)

// Scanner is the contract every service scanner must satisfy.
//
// To add a new AWS service, create a file in this package (e.g., rds.go),
// define a struct, and implement both methods below. The rest of the engine
// will automatically pick it up — no registration required as long as you
// append your scanner to the slice returned by AllScanners() (once that
// function exists).
type Scanner interface {
	// Scan performs all security checks for this service and returns every
	// finding that was detected. It must respect ctx cancellation — check
	// ctx.Done() or pass ctx to any AWS SDK calls so the scan can be
	// interrupted cleanly (e.g., on timeout or user request).
	//
	// A non-nil error indicates a failure to complete the scan (e.g., missing
	// credentials, API rate limit). Partial results may still be returned
	// alongside the error — callers should handle both.
	Scan(ctx context.Context) ([]models.Finding, error)

	// ServiceName returns the short, uppercase AWS service name this scanner
	// covers (e.g., "S3", "EC2", "IAM", "CloudTrail"). Used for logging,
	// metrics, and associating findings with a service in the UI.
	ServiceName() string
}

// ScanResult bundles the output of a single scanner run together with
// identifying metadata. This makes it easy to collect results from multiple
// scanners running concurrently — each goroutine sends one ScanResult on a
// shared channel, and the caller reassembles them without needing locks.
//
// Example usage with goroutines:
//
//	results := make(chan ScanResult, len(scanners))
//	for _, s := range scanners {
//	    go func(s Scanner) {
//	        findings, err := s.Scan(ctx)
//	        results <- ScanResult{ServiceName: s.ServiceName(), Findings: findings, Err: err}
//	    }(s)
//	}
type ScanResult struct {
	// ServiceName mirrors Scanner.ServiceName() so the result is self-describing
	// after the scanner goroutine exits.
	ServiceName string

	// Findings holds every misconfiguration detected during the scan.
	// This slice is nil (not empty) when the scan failed entirely.
	Findings []models.Finding

	// Err is non-nil if the scan could not complete successfully.
	// The caller should log this and continue processing other results.
	Err error
}
