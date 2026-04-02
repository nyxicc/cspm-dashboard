import { useState } from 'react';
import FilterBar          from './FilterBar';
import FindingsRow        from './FindingsRow';
import FindingDetailModal from './FindingDetailModal';
import ErrorBanner        from '../shared/ErrorBanner/ErrorBanner';
import { exportToCSV }    from '../../utils/export';
import styles from './FindingsTable.module.css';

// Number of skeleton rows to show while data is loading.
const SKELETON_ROWS = 8;

export default function FindingsTable({ findings, loading, error }) {
  // Filter state is local — no other component needs to know about it.
  const [severityFilter,  setSeverityFilter]  = useState('');
  const [serviceFilter,   setServiceFilter]   = useState('');
  // selectedFinding drives the detail modal — null when closed.
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Derive filtered list during render — no extra state needed.
  const filtered = findings
    .filter(f => !severityFilter || f.severity === severityFilter)
    .filter(f => !serviceFilter  || f.service  === serviceFilter);

  return (
    <div className={styles.wrapper}>
      <div className={styles.toolbar}>
        <FilterBar
          severityFilter={severityFilter}
          serviceFilter={serviceFilter}
          onSeverityChange={setSeverityFilter}
          onServiceChange={setServiceFilter}
        />
        <div className={styles.toolbarRight}>
          {!loading && !error && (
            <span className={styles.resultCount}>
              {filtered.length} {filtered.length === 1 ? 'finding' : 'findings'}
              {(severityFilter || serviceFilter) && ` (filtered from ${findings.length})`}
            </span>
          )}
          <button
            className={styles.exportBtn}
            onClick={() => exportToCSV(filtered)}
            disabled={loading || filtered.length === 0}
            title="Download findings as a CSV file (opens in Excel)"
          >
            ↓ Export CSV {!loading && filtered.length > 0 && `(${filtered.length})`}
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      <div className={styles.tableScroll}>
        <table className={styles.table}>
          <colgroup>
            <col style={{ width: '100px' }} />  {/* Severity */}
            <col style={{ width: '90px' }} />   {/* Service */}
            <col />                             {/* Title — auto */}
            <col style={{ width: '110px' }} />  {/* CIS Control */}
            <col style={{ width: '120px' }} />  {/* Region */}
            <col style={{ width: '165px' }} />  {/* Timestamp */}
          </colgroup>
          <thead>
            <tr className={styles.headRow}>
              <th className={styles.th}>Severity</th>
              <th className={styles.th}>Service</th>
              <th className={styles.th}>Title</th>
              <th className={styles.th}>CIS Control</th>
              <th className={styles.th}>Region</th>
              <th className={styles.th}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              // Skeleton rows while data is in-flight
              Array.from({ length: SKELETON_ROWS }).map((_, i) => (
                <tr key={i} className={styles.skeletonRow}>
                  {Array.from({ length: 6 }).map((_, j) => (
                    <td key={j} className={styles.skeletonCell}>
                      <div className={`${styles.skeletonLine} skeleton`} />
                    </td>
                  ))}
                </tr>
              ))
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  {findings.length === 0
                    ? 'No findings detected — your account looks clean.'
                    : 'No findings match the selected filters.'}
                </td>
              </tr>
            ) : (
              filtered.map(f => (
                <FindingsRow
                  key={f.id}
                  finding={f}
                  onClick={() => setSelectedFinding(f)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Modal renders via portal into document.body, outside overflow:hidden */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
