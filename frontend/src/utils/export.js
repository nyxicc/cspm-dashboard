import { formatTimestamp } from './severity';

// CSV column definitions — order mirrors the table then adds all hidden fields.
const COLUMNS = [
  { header: 'Severity',             field: f => f.severity },
  { header: 'Service',              field: f => f.service },
  { header: 'Title',                field: f => f.title },
  { header: 'Description',          field: f => f.description },
  { header: 'Recommendation',       field: f => f.recommendation },
  { header: 'CIS Control',          field: f => f.cis_control || '' },
  { header: 'Region',               field: f => f.region },
  { header: 'Resource Name',        field: f => f.resource_name },
  { header: 'Resource Type',        field: f => f.resource_type },
  { header: 'Resource ID',          field: f => f.resource_id },
  { header: 'Account ID',           field: f => f.account_id },
  { header: 'Status',               field: f => f.status },
  { header: 'Compliance Frameworks',field: f => (f.compliance_frameworks ?? []).join('; ') },
  { header: 'Timestamp',            field: f => formatTimestamp(f.timestamp) },
];

// Wraps a cell value in quotes and escapes any internal double-quotes per RFC 4180.
function escapeCell(value) {
  const str = value == null ? '' : String(value);
  return `"${str.replace(/"/g, '""')}"`;
}

// exportToCSV triggers a browser download of the findings as a .csv file.
// The file is named with today's date so multiple exports don't overwrite each other.
// Exported rows respect the caller's filtering — pass `filtered` not `all`.
export function exportToCSV(findings) {
  if (!findings || findings.length === 0) return;

  const header = COLUMNS.map(c => escapeCell(c.header)).join(',');
  const rows   = findings.map(f =>
    COLUMNS.map(c => escapeCell(c.field(f))).join(',')
  );

  const csv  = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);

  const date     = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const filename = `cspm-findings-${date}.csv`;

  // Create a temporary <a> and programmatically click it — the browser
  // interprets this as a user-initiated download and saves the file.
  const a = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();

  // Release the object URL so the browser can reclaim the memory.
  URL.revokeObjectURL(url);
}
