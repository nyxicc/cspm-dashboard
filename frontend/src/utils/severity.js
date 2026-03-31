// Single source of truth for severity ordering and display values.
// Components should import from here rather than hard-coding strings.

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

export const SEVERITY_LABELS = {
  critical: 'Critical',
  high:     'High',
  medium:   'Medium',
  low:      'Low',
};

export const SEVERITY_DESCRIPTIONS = {
  critical: 'Immediate risk of compromise. Publicly exposed resources, missing encryption on sensitive data, or root account misuse. Remediate within 24 hours.',
  high:     'Significant exposure that could be exploited with low effort. Overly permissive policies, unrestricted inbound ports, or missing MFA. Remediate within 72 hours.',
  medium:   'Increases attack surface or weakens defense-in-depth. Best-practice gaps like missing log validation or unversioned buckets. Remediate within 30 days.',
  low:      'Minor hygiene issue with limited direct impact. Often informational or compensating controls are already in place. Remediate at next maintenance window.',
};

// Returns the worst severity present in a findings array, or null if empty.
// "Worst" is determined by position in SEVERITY_ORDER (index 0 = most severe).
export function worstSeverity(findings) {
  if (!findings || findings.length === 0) return null;
  return SEVERITY_ORDER.find(sev => findings.some(f => f.severity === sev)) ?? null;
}

// Formats an ISO timestamp into a short, readable string.
export function formatTimestamp(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('en-US', {
    month:  'short',
    day:    'numeric',
    year:   'numeric',
    hour:   '2-digit',
    minute: '2-digit',
  });
}
