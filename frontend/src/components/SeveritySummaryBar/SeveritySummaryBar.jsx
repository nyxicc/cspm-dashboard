import SeverityBadge from '../shared/SeverityBadge/SeverityBadge';
import ErrorBanner   from '../shared/ErrorBanner/ErrorBanner';
import { SEVERITY_ORDER, SEVERITY_LABELS, SEVERITY_DESCRIPTIONS, formatTimestamp } from '../../utils/severity';
import styles from './SeveritySummaryBar.module.css';

export default function SeveritySummaryBar({ summary, loading, error }) {
  if (error) return <ErrorBanner message={error} />;

  if (loading) {
    return (
      <div className={styles.bar}>
        <div className={styles.badges}>
          {SEVERITY_ORDER.map(sev => (
            <div key={sev} className={`${styles.skeletonBadge} skeleton`} />
          ))}
        </div>
        <div className={`${styles.skeletonMeta} skeleton`} />
      </div>
    );
  }

  if (!summary) return null;

  const { by_severity, total_findings, scanned_at, duration_ms } = summary;

  return (
    <div className={styles.bar}>
      <div className={styles.badges}>
        {SEVERITY_ORDER.map(sev => (
          <div key={sev} className={styles.badgeWrapper}>
            <span className={styles.bigCount} style={{ color: `var(--sev-${sev})` }}>
              {by_severity[sev] ?? 0}
            </span>
            <SeverityBadge severity={sev} size="sm" />
            <div className={styles.tooltip} style={{ borderTopColor: `var(--sev-${sev})` }}>
              <span className={styles.tooltipLabel}>{SEVERITY_LABELS[sev]}</span>
              {SEVERITY_DESCRIPTIONS[sev]}
            </div>
          </div>
        ))}
      </div>

      <div className={styles.meta}>
        <span className={styles.total}>
          <strong>{total_findings}</strong> total findings
        </span>
        <span className={styles.separator}>·</span>
        <span className={styles.timestamp}>
          Scanned {formatTimestamp(scanned_at)}
        </span>
        <span className={styles.separator}>·</span>
        <span className={styles.duration}>{(duration_ms / 1000).toFixed(1)}s</span>
      </div>
    </div>
  );
}
