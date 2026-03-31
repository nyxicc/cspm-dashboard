import { SEVERITY_ORDER, worstSeverity } from './severity';

// The four services covered by this tool's scanners. Hardcoded so that
// a service with zero findings still gets a card (a clean bill of health
// is information worth showing).
export const KNOWN_SERVICES = ['S3', 'IAM', 'EC2', 'CloudTrail'];

// deriveServiceCards transforms the raw findings array from /api/scan into
// one summary object per service, suitable for rendering ServiceCard components.
//
// Returns an array of four objects, always in KNOWN_SERVICES order:
//   { service, totalFindings, bySeverity, worstSeverity }
export function deriveServiceCards(findings) {
  // Bucket findings by service
  const grouped = Object.fromEntries(KNOWN_SERVICES.map(s => [s, []]));
  for (const f of findings) {
    if (grouped[f.service] !== undefined) {
      grouped[f.service].push(f);
    }
  }

  return KNOWN_SERVICES.map(service => {
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
