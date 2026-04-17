package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"cspm-dashboard/backend/models"
)

// RDSScanner checks every RDS DB instance in the region for common security
// misconfigurations. It implements the Scanner interface.
type RDSScanner struct {
	client    *rds.Client
	accountID string
	region    string
}

// NewRDSScanner creates an RDSScanner from an already-configured AWS SDK config.
func NewRDSScanner(cfg aws.Config, accountID string) *RDSScanner {
	return &RDSScanner{
		client:    rds.NewFromConfig(cfg),
		accountID: accountID,
		region:    cfg.Region,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *RDSScanner) ServiceName() string { return "RDS" }

// Scan paginates over every RDS DB instance in the region and runs all
// security checks against each one. A failed check on one instance is skipped
// rather than aborting the rest of the scan.
func (s *RDSScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	paginator := rds.NewDescribeDBInstancesPaginator(s.client, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("rds: describing DB instances: %w", err)
		}

		for _, db := range page.DBInstances {
			if f := s.checkPubliclyAccessible(db); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkStorageEncryption(db); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkBackupRetention(db); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkDeletionProtection(db); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkAutoMinorVersionUpgrade(db); f != nil {
				findings = append(findings, *f)
			}
			if f := s.checkMultiAZ(db); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

// checkPubliclyAccessible detects RDS instances reachable from the internet.
//
// Why it matters (CIS 2.3.3):
// A publicly accessible instance has its endpoint resolve to a public IP.
// Even with a restrictive security group, the instance is exposed to scanning,
// brute-force, and any future SG misconfiguration. Database servers should
// always sit in private subnets with no public endpoint.
func (s *RDSScanner) checkPubliclyAccessible(db rdstypes.DBInstance) *models.Finding {
	if !aws.ToBool(db.PubliclyAccessible) {
		return nil
	}
	id := aws.ToString(db.DBInstanceIdentifier)
	return s.newFinding(db,
		models.SeverityCritical,
		"RDS instance is publicly accessible",
		fmt.Sprintf(
			"DB instance '%s' has PubliclyAccessible=true. Its DNS endpoint resolves "+
				"to a public IP, meaning any host on the internet can attempt to connect "+
				"and exploit unpatched engine vulnerabilities or weak credentials.",
			id),
		fmt.Sprintf(
			"Modify '%s' to disable public accessibility. Place the instance in a private "+
				"subnet and restrict inbound access via security groups to the application "+
				"tier only. Use RDS Proxy or a bastion host for administrative access.",
			id),
		"2.3.3",
	)
}

// checkStorageEncryption detects RDS instances with unencrypted storage.
//
// Why it matters (CIS 2.3.1):
// Unencrypted storage means the underlying EBS volumes, automated backups,
// read replicas, and snapshots are all stored in plaintext. An accidentally
// shared snapshot or physical-level storage access exposes the full database.
func (s *RDSScanner) checkStorageEncryption(db rdstypes.DBInstance) *models.Finding {
	if aws.ToBool(db.StorageEncrypted) {
		return nil
	}
	id := aws.ToString(db.DBInstanceIdentifier)
	return s.newFinding(db,
		models.SeverityHigh,
		"RDS instance storage is not encrypted",
		fmt.Sprintf(
			"DB instance '%s' does not have storage encryption enabled. The underlying "+
				"EBS volumes, backups, and snapshots are stored in plaintext. An accidentally "+
				"shared snapshot exposes the full database contents without any key access.",
			id),
		fmt.Sprintf(
			"RDS encryption cannot be toggled on a live instance. To encrypt '%s': "+
				"(1) create an encrypted snapshot, (2) restore a new instance from it, "+
				"(3) update connection strings and promote the new instance. Enable the "+
				"account-level RDS default encryption to prevent future unencrypted instances.",
			id),
		"2.3.1",
	)
}

// checkBackupRetention detects RDS instances where automated backup retention
// is less than 7 days (or disabled entirely, which sets retention to 0).
//
// Why it matters:
// Short backup retention windows limit point-in-time recovery options. If data
// corruption or a ransomware attack is not discovered within the retention
// window, there may be no clean restore point available.
func (s *RDSScanner) checkBackupRetention(db rdstypes.DBInstance) *models.Finding {
	retention := aws.ToInt32(db.BackupRetentionPeriod)
	if retention >= 7 {
		return nil
	}
	id := aws.ToString(db.DBInstanceIdentifier)
	return s.newFinding(db,
		models.SeverityMedium,
		"RDS automated backup retention is less than 7 days",
		fmt.Sprintf(
			"DB instance '%s' has a backup retention period of %d day(s). A retention "+
				"period under 7 days limits point-in-time recovery options and reduces "+
				"resilience against data corruption or ransomware that is not caught quickly.",
			id, retention),
		fmt.Sprintf(
			"Increase the backup retention period for '%s' to at least 7 days "+
				"(30 days recommended for production). This change takes effect immediately "+
				"and does not require instance downtime.",
			id),
		"",
	)
}

// checkDeletionProtection detects RDS instances without deletion protection.
//
// Why it matters:
// Without deletion protection, a single API call (rds:DeleteDBInstance) from
// a compromised credential, a misconfigured IaC pipeline, or a human error
// can permanently destroy the database and its automated backups.
func (s *RDSScanner) checkDeletionProtection(db rdstypes.DBInstance) *models.Finding {
	if aws.ToBool(db.DeletionProtection) {
		return nil
	}
	id := aws.ToString(db.DBInstanceIdentifier)
	return s.newFinding(db,
		models.SeverityMedium,
		"RDS instance does not have deletion protection enabled",
		fmt.Sprintf(
			"DB instance '%s' can be deleted without disabling deletion protection first. "+
				"A compromised credential with rds:DeleteDBInstance, a misconfigured "+
				"automation script, or an accidental CLI command can permanently destroy "+
				"the database with no immediate recovery path.",
			id),
		fmt.Sprintf(
			"Enable deletion protection on '%s'. This adds a guard that requires the "+
				"flag to be explicitly disabled before the instance can be deleted. It has "+
				"no effect on normal operations, maintenance, or automated backups.",
			id),
		"",
	)
}

// checkAutoMinorVersionUpgrade detects RDS instances with automatic minor version
// upgrades disabled.
//
// Why it matters (RDS.13):
// Minor version upgrades often include security patches for the database engine.
// Disabling automatic upgrades means the instance may run a version with known
// vulnerabilities indefinitely until manually patched. Automatic upgrades apply
// during the configured maintenance window with minimal downtime.
func (s *RDSScanner) checkAutoMinorVersionUpgrade(db rdstypes.DBInstance) *models.Finding {
	if aws.ToBool(db.AutoMinorVersionUpgrade) {
		return nil
	}
	id := aws.ToString(db.DBInstanceIdentifier)
	return s.newFinding(db,
		models.SeverityLow,
		"RDS instance does not have automatic minor version upgrades enabled",
		fmt.Sprintf(
			"DB instance '%s' has AutoMinorVersionUpgrade=false. Minor version upgrades "+
				"frequently include security patches. Without automatic upgrades, the instance "+
				"may run a database engine version with known CVEs until it is manually patched.",
			id),
		fmt.Sprintf(
			"Enable automatic minor version upgrades on '%s' via the RDS console or: "+
				"'aws rds modify-db-instance --db-instance-identifier %s "+
				"--auto-minor-version-upgrade --apply-immediately'. "+
				"Upgrades apply during the configured maintenance window.",
			id, id),
		"RDS.13",
	)
}

// checkMultiAZ detects RDS instances not deployed across multiple Availability Zones.
//
// Why it matters (RDS.15):
// A single-AZ RDS instance has no automatic failover. If the Availability Zone
// experiences an outage (hardware failure, power disruption, network partition),
// the database is unavailable and data may be at risk. Multi-AZ provides a
// synchronous standby replica in a different AZ with automatic failover, typically
// completing in 1-2 minutes.
func (s *RDSScanner) checkMultiAZ(db rdstypes.DBInstance) *models.Finding {
	if aws.ToBool(db.MultiAZ) {
		return nil
	}
	id := aws.ToString(db.DBInstanceIdentifier)
	return s.newFinding(db,
		models.SeverityMedium,
		"RDS instance is not configured for Multi-AZ deployment",
		fmt.Sprintf(
			"DB instance '%s' is deployed in a single Availability Zone. A zone-level "+
				"failure (hardware, power, or network) would make this database unavailable "+
				"with no automatic failover path. Recovery would require manual intervention "+
				"or restoring from an automated backup.",
			id),
		fmt.Sprintf(
			"Enable Multi-AZ on '%s': in the RDS console modify the instance and enable "+
				"'Multi-AZ deployment', or: 'aws rds modify-db-instance --db-instance-identifier "+
				"%s --multi-az --apply-immediately'. Note: enabling Multi-AZ causes a brief "+
				"failover (~60s) when applied immediately.",
			id, id),
		"RDS.15",
	)
}

// newFinding constructs an RDS finding with all shared fields populated.
func (s *RDSScanner) newFinding(
	db rdstypes.DBInstance,
	severity models.Severity,
	title, description, recommendation, cisControl string,
) *models.Finding {
	return &models.Finding{
		ID:                   generateID(),
		ResourceID:           aws.ToString(db.DBInstanceArn),
		ResourceType:         "AWS::RDS::DBInstance",
		ResourceName:         aws.ToString(db.DBInstanceIdentifier),
		Service:              s.ServiceName(),
		Severity:             severity,
		Title:                title,
		Description:          description,
		Recommendation:       recommendation,
		CISControl:           cisControl,
		ComplianceFrameworks: []string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
		Region:               s.region,
		AccountID:            s.accountID,
		Status:               models.StatusOpen,
		Timestamp:            time.Now().UTC(),
	}
}
