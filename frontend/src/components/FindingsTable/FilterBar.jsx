import { SEVERITY_ORDER, SEVERITY_LABELS } from '../../utils/severity';
import { KNOWN_SERVICES } from '../../utils/compliance';
import styles from './FilterBar.module.css';

export default function FilterBar({
  severityFilter,
  serviceFilter,
  onSeverityChange,
  onServiceChange,
}) {
  return (
    <div className={styles.bar}>
      <select
        className={styles.select}
        value={severityFilter}
        onChange={e => onSeverityChange(e.target.value)}
        aria-label="Filter by severity"
      >
        <option value="">All Severities</option>
        {SEVERITY_ORDER.map(sev => (
          <option key={sev} value={sev}>{SEVERITY_LABELS[sev]}</option>
        ))}
      </select>

      <select
        className={styles.select}
        value={serviceFilter}
        onChange={e => onServiceChange(e.target.value)}
        aria-label="Filter by service"
      >
        <option value="">All Services</option>
        {KNOWN_SERVICES.map(svc => (
          <option key={svc} value={svc}>{svc}</option>
        ))}
      </select>
    </div>
  );
}
