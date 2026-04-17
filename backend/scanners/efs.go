package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"

	"cspm-dashboard/backend/models"
)

// EFSScanner checks every EFS file system in the region for encryption at rest.
// It implements the Scanner interface.
type EFSScanner struct {
	client    *efs.Client
	accountID string
	region    string
}

// NewEFSScanner creates an EFSScanner from an already-configured AWS SDK config.
func NewEFSScanner(cfg aws.Config, accountID string) *EFSScanner {
	return &EFSScanner{
		client:    efs.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *EFSScanner) ServiceName() string { return "EFS" }

// Scan lists every EFS file system in the region and checks each one for
// encryption at rest.
func (s *EFSScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	var marker *string
	for {
		out, err := s.client.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("efs: describing file systems: %w", err)
		}

		for _, fs := range out.FileSystems {
			if f := s.checkEncryption(fs); f != nil {
				findings = append(findings, *f)
			}
		}

		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}

	return findings, nil
}

// checkEncryption detects EFS file systems that are not encrypted at rest.
//
// Why it matters (EFS.1, EFS.8):
// An unencrypted EFS file system stores all data in plaintext on the underlying
// storage. If the storage media is compromised, cloned, or accessed by a
// misconfigured mount target, data is readable without any additional
// authentication. Encryption at rest ensures data is protected by a KMS key
// even if the underlying storage is accessed directly.
//
// Note: EFS encryption at rest can only be enabled at creation time — it cannot
// be toggled on an existing file system. The only remediation path is to create
// a new encrypted file system and migrate data.
func (s *EFSScanner) checkEncryption(fs efstypes.FileSystemDescription) *models.Finding {
	if aws.ToBool(fs.Encrypted) {
		return nil
	}

	fsID := aws.ToString(fs.FileSystemId)
	fsARN := aws.ToString(fs.FileSystemArn)
	fsName := fsID
	if fs.Name != nil {
		fsName = aws.ToString(fs.Name)
	}

	return &models.Finding{
		ID:           generateID(),
		ResourceID:   fsARN,
		ResourceType: "AWS::EFS::FileSystem",
		ResourceName: fsName,
		Service:      s.ServiceName(),
		Severity:     models.SeverityHigh,
		Title:        "EFS file system is not encrypted at rest",
		Description: fmt.Sprintf(
			"EFS file system '%s' (%s) in region %s is not encrypted at rest. "+
				"All data stored on this file system is in plaintext. A compromised "+
				"EC2 instance with access to the mount target, or direct storage-level "+
				"access, can read all file contents without any key material.",
			fsName, fsID, s.region),
		Recommendation: fmt.Sprintf(
			"EFS encryption at rest cannot be enabled on an existing file system. "+
				"To remediate '%s': (1) create a new EFS file system with encryption enabled, "+
				"(2) mount both the old and new file systems on an EC2 instance, "+
				"(3) copy all data using rsync or aws datasync, "+
				"(4) update all mount targets and application configurations to use the new FS, "+
				"(5) delete the unencrypted file system after verifying the migration.",
			fsID),
		CISControl:           "EFS.1",
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}
