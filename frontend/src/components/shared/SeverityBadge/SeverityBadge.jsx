import styles from './SeverityBadge.module.css';

// SeverityBadge renders a colored pill for a given severity level and count.
// size='md' (default) is used in the summary bar and table rows.
// size='sm' is used inside service cards for the mini severity breakdown.
export default function SeverityBadge({ severity, count, size = 'md' }) {
  return (
    <span
      className={`${styles.badge} ${styles[severity]} ${styles[size]}`}
      data-severity={severity}
    >
      {count !== undefined && <span className={styles.count}>{count}</span>}
      <span className={styles.label}>{severity}</span>
    </span>
  );
}
