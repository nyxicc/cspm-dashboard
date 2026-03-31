import SeverityBadge from '../shared/SeverityBadge/SeverityBadge';
import { SEVERITY_ORDER } from '../../utils/severity';
import styles from './ServiceCard.module.css';

// Icon characters for each AWS service — simple text glyphs, no icon library needed.
const SERVICE_ICONS = {
  S3:          '🗄',
  IAM:         '🔑',
  EC2:         '⚙',
  CloudTrail:  '📋',
};

export default function ServiceCard({ service, totalFindings, bySeverity, worstSeverity }) {
  const isClean = worstSeverity === null;
  // The left border color reflects the worst severity found.
  // When clean, use green to signal a healthy service.
  const borderColor = `var(--sev-${worstSeverity ?? 'low'})`;

  return (
    <div className={styles.card} style={{ borderLeftColor: borderColor }}>
      <div className={styles.header}>
        <span className={styles.icon}>{SERVICE_ICONS[service] ?? '☁'}</span>
        <div>
          <p className={styles.service}>{service}</p>
          <p className={styles.count}>
            {isClean
              ? <span className={styles.clean}>No issues found</span>
              : <><strong>{totalFindings}</strong> {totalFindings === 1 ? 'issue' : 'issues'} found</>
            }
          </p>
        </div>
      </div>

      <div className={styles.breakdown}>
        {SEVERITY_ORDER.map(sev => {
          const count = bySeverity[sev] ?? 0;
          return (
            // Dim badges for zero-count severities so the non-zero ones stand out.
            <span
              key={sev}
              className={styles.badgeWrap}
              style={{ opacity: count === 0 ? 0.3 : 1 }}
            >
              <SeverityBadge severity={sev} count={count} size="sm" />
            </span>
          );
        })}
      </div>
    </div>
  );
}
