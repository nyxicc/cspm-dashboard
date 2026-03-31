import { useEffect } from 'react';
import { createPortal } from 'react-dom';
import SeverityBadge from '../shared/SeverityBadge/SeverityBadge';
import { formatTimestamp } from '../../utils/severity';
import styles from './FindingDetailModal.module.css';

// FindingDetailModal renders a full-detail panel for a single finding.
// It is mounted via createPortal into document.body so it escapes the
// table wrapper's overflow:hidden and always renders on top of everything.
export default function FindingDetailModal({ finding, onClose }) {
  // Close on Escape key — attach listener when modal is open, clean up on close.
  useEffect(() => {
    if (!finding) return;
    const handler = e => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [finding, onClose]);

  if (!finding) return null;

  const {
    severity, service, title, description, recommendation,
    resource_name, resource_type, resource_id, account_id, region,
    cis_control, compliance_frameworks, status, timestamp,
  } = finding;

  const severityBorderColor = `var(--sev-${severity})`;

  return createPortal(
    // Backdrop — clicking it closes the modal. stopPropagation on the panel
    // prevents clicks inside the modal from bubbling up to the backdrop.
    <div
      className={styles.backdrop}
      onClick={onClose}
      role="presentation"
    >
      <div
        className={styles.panel}
        style={{ borderLeftColor: severityBorderColor }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        {/* ── Header ───────────────────────────────────────── */}
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <SeverityBadge severity={severity} size="md" />
            <h2 className={styles.title}>{title}</h2>
          </div>
          <button
            className={styles.closeBtn}
            onClick={onClose}
            aria-label="Close finding detail"
          >
            ✕
          </button>
        </div>

        {/* ── Body ─────────────────────────────────────────── */}
        <div className={styles.body}>

          {/* Description */}
          <Section label="Description">
            <p className={styles.prose}>{description}</p>
          </Section>

          {/* Recommendation */}
          <Section label="Recommendation">
            <p className={styles.prose}>{recommendation}</p>
          </Section>

          {/* Resource */}
          <Section label="Resource">
            <dl className={styles.dl}>
              <Row label="Name"    value={resource_name} />
              <Row label="Type"    value={resource_type} />
              <Row label="ID / ARN" value={resource_id}  mono />
              <Row label="Account" value={account_id}    mono />
              <Row label="Region"  value={region} />
            </dl>
          </Section>

          {/* Compliance */}
          <Section label="Compliance">
            <dl className={styles.dl}>
              <Row label="CIS Control" value={cis_control || '—'} mono />
              <div className={styles.row}>
                <dt className={styles.dt}>Frameworks</dt>
                <dd className={styles.dd}>
                  {compliance_frameworks && compliance_frameworks.length > 0 ? (
                    <div className={styles.pills}>
                      {compliance_frameworks.map(fw => (
                        <span key={fw} className={styles.pill}>{fw}</span>
                      ))}
                    </div>
                  ) : '—'}
                </dd>
              </div>
              <Row label="Status" value={status} />
            </dl>
          </Section>

          {/* Metadata */}
          <Section label="Details">
            <dl className={styles.dl}>
              <Row label="Service"  value={service} />
              <Row label="Detected" value={formatTimestamp(timestamp)} />
            </dl>
          </Section>

        </div>
      </div>
    </div>,
    document.body
  );
}

// Section — a titled group of content within the modal body.
function Section({ label, children }) {
  return (
    <section className={styles.section}>
      <h3 className={styles.sectionLabel}>{label}</h3>
      {children}
    </section>
  );
}

// Row — a single key/value pair inside a <dl>.
function Row({ label, value, mono }) {
  return (
    <div className={styles.row}>
      <dt className={styles.dt}>{label}</dt>
      <dd className={`${styles.dd} ${mono ? styles.mono : ''}`}>{value || '—'}</dd>
    </div>
  );
}
