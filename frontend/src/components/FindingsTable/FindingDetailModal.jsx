import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import SeverityBadge from '../shared/SeverityBadge/SeverityBadge';
import { formatTimestamp } from '../../utils/severity';
import { fetchExplain } from '../../api/client';
import styles from './FindingDetailModal.module.css';

export default function FindingDetailModal({ finding, onClose }) {
  const [aiState, setAiState] = useState({ loading: false, sections: null, error: null });

  useEffect(() => {
    if (!finding) return;
    const handler = e => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [finding, onClose]);

  useEffect(() => {
    if (!finding) {
      setAiState({ loading: false, sections: null, error: null });
      return;
    }
    setAiState({ loading: true, sections: null, error: null });
    fetchExplain(finding)
      .then(data => setAiState({ loading: false, sections: parseAI(data.explanation), error: null }))
      .catch(err  => setAiState({ loading: false, sections: null, error: err.message }));
  }, [finding]);

  if (!finding) return null;

  const {
    severity, service, title, description, recommendation,
    resource_name, resource_type, resource_id, account_id, region,
    cis_control, compliance_frameworks, status, timestamp,
  } = finding;

  return createPortal(
    <div className={styles.backdrop} onClick={onClose} role="presentation">
      <div
        className={styles.panel}
        style={{ borderLeftColor: `var(--sev-${severity})` }}
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
          <button className={styles.closeBtn} onClick={onClose} aria-label="Close">✕</button>
        </div>

        {/* ── Body ─────────────────────────────────────────── */}
        <div className={styles.body}>

          {/* AI Risk Analysis */}
          <section className={styles.section}>
            <h3 className={styles.sectionLabel}>AI Risk Analysis</h3>
            {aiState.loading && (
              <div className={styles.aiLoading}>
                <div className={styles.spinner} />
                <span className={styles.aiLoadingText}>Analysing with AI…</span>
              </div>
            )}
            {aiState.error && (
              <p className={styles.aiError}>{aiState.error}</p>
            )}
            {aiState.sections && (
              <div className={styles.aiCards}>
                {aiState.sections.map(({ label, text, accent }) => (
                  <div key={label} className={styles.aiCard} style={{ '--accent': accent }}>
                    <span className={styles.aiCardLabel}>{label}</span>
                    <p className={styles.aiCardText}>{text}</p>
                  </div>
                ))}
              </div>
            )}
          </section>

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
              <Row label="Name"     value={resource_name} />
              <Row label="Type"     value={resource_type} />
              <Row label="ID / ARN" value={resource_id}   mono />
              <Row label="Account"  value={account_id}    mono />
              <Row label="Region"   value={region} />
            </dl>
          </Section>

          {/* Compliance */}
          <Section label="Compliance">
            <dl className={styles.dl}>
              <Row label="CIS Control" value={cis_control || '—'} mono />
              <div className={styles.row}>
                <dt className={styles.dt}>Frameworks</dt>
                <dd className={styles.dd}>
                  {compliance_frameworks?.length > 0 ? (
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

// parseAI splits the structured AI response into labelled sections.
// Each line matching **Label:** text becomes a card. Unknown labels fall back
// to a neutral accent. Plain text with no labels renders as a single card.
const SECTION_ACCENTS = {
  "What it is":        "#58a6ff",
  "Why it's dangerous": "#f97316",
  "Attack scenario":   "#ef4444",
  "Immediate fix":     "#22c55e",
};

function parseAI(raw) {
  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
  const sections = [];
  let label = null;
  let chunks = [];

  for (const line of lines) {
    const m = line.match(/^\*\*([^*]+)\*\*[:\s]*(.*)/);
    if (m) {
      if (label) sections.push({ label, text: chunks.join(' '), accent: SECTION_ACCENTS[label] ?? '#58a6ff' });
      label = m[1];
      chunks = m[2] ? [m[2]] : [];
    } else {
      chunks.push(line);
    }
  }
  if (label) sections.push({ label, text: chunks.join(' '), accent: SECTION_ACCENTS[label] ?? '#58a6ff' });

  // Fallback: no labels found — return the whole thing as one block
  if (sections.length === 0) {
    return [{ label: 'Analysis', text: raw.trim(), accent: '#58a6ff' }];
  }
  return sections;
}

function Section({ label, children }) {
  return (
    <section className={styles.section}>
      <h3 className={styles.sectionLabel}>{label}</h3>
      {children}
    </section>
  );
}

function Row({ label, value, mono }) {
  return (
    <div className={styles.row}>
      <dt className={styles.dt}>{label}</dt>
      <dd className={`${styles.dd} ${mono ? styles.mono : ''}`}>{value || '—'}</dd>
    </div>
  );
}
