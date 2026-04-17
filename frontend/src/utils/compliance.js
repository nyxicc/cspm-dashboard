import { SEVERITY_ORDER, worstSeverity } from './severity';

// AWS services covered by this tool's scanners.
export const AWS_SERVICES = ['S3', 'IAM', 'EC2', 'CloudTrail', 'RDS', 'KMS'];

// Azure services covered by this tool's scanners.
export const AZURE_SERVICES = ['BlobStorage', 'VirtualMachines', 'EntraID', 'AzureSQL', 'ActivityLog', 'KeyVault'];

// KNOWN_SERVICES kept for backward compatibility — defaults to AWS.
export const KNOWN_SERVICES = AWS_SERVICES;

// deriveServiceCards transforms the raw findings array from /api/scan into
// one summary object per service, suitable for rendering ServiceCard components.
//
// Pass the provider-specific service list as the second argument.
// Returns one object per service, always in the given services order:
//   { service, totalFindings, bySeverity, worstSeverity }
export function deriveServiceCards(findings, services = AWS_SERVICES) {
  // Bucket findings by service
  const grouped = Object.fromEntries(services.map(s => [s, []]));
  for (const f of findings) {
    if (grouped[f.service] !== undefined) {
      grouped[f.service].push(f);
    }
  }

  return services.map(service => {
    const serviceFindings = grouped[service];

    // Count per severity — always initialised to 0 so the UI never deals with undefined
    const bySeverity = Object.fromEntries(SEVERITY_ORDER.map(s => [s, 0]));
    for (const f of serviceFindings) {
      if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++;
    }

    return {
      service,
      totalFindings: serviceFindings.length,
      bySeverity,
      worstSeverity: worstSeverity(serviceFindings), // null when clean
    };
  });
}
