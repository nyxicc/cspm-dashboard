import SeverityBadge from '../shared/SeverityBadge/SeverityBadge';
import { formatTimestamp } from '../../utils/severity';
import styles from './FindingsRow.module.css';

export default function FindingsRow({ finding, onClick }) {
  const {
    severity,
    service,
    title,
    cis_control,
    region,
    timestamp,
    description,
    recommendation,
  } = finding;

  return (
    <tr
      className={styles.row}
      data-severity={severity}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') onClick?.(); }}
      aria-label={`View details for: ${title}`}
    >
      <td className={styles.cell}>
        <SeverityBadge severity={severity} size="sm" />
      </td>
      <td className={`${styles.cell} ${styles.service}`}>{service}</td>
      <td className={`${styles.cell} ${styles.title}`}>
        <span className={styles.titleText} title={title}>{title}</span>
        {/* Expandable description shown on hover via CSS — no JS needed */}
        <span className={styles.description} title={description + '\n\n' + recommendation}>
          {description}
        </span>
      </td>
      <td className={`${styles.cell} ${styles.mono}`}>{cis_control || '—'}</td>
      <td className={`${styles.cell} ${styles.mono}`}>{region}</td>
      <td className={`${styles.cell} ${styles.timestamp}`}>{formatTimestamp(timestamp)}</td>
    </tr>
  );
}
