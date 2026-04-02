import { useEffect, useMemo, useState } from 'react';
import { fetchAttackPaths } from '../../api/client';
import AttackGraph from './AttackGraph';
import SeverityBadge from '../shared/SeverityBadge/SeverityBadge';
import FindingDetailModal from '../FindingsTable/FindingDetailModal';
import styles from './AttackPaths.module.css';

// MITRE ATT&CK tactics shown in the legend at the bottom of the page.
const MITRE_TACTICS = [
  { name: 'Initial Access',       color: '#ef4444' },
  { name: 'Execution',            color: '#f97316' },
  { name: 'Persistence',          color: '#eab308' },
  { name: 'Privilege Escalation', color: '#fb923c' },
  { name: 'Defense Evasion',      color: '#a855f7' },
  { name: 'Credential Access',    color: '#f59e0b' },
  { name: 'Discovery',            color: '#58a6ff' },
  { name: 'Lateral Movement',     color: '#f59e0b' },
  { name: 'Exfiltration',         color: '#b91c1c' },
  { name: 'Impact',               color: '#dc2626' },
];

export default function AttackPaths({ findings }) {
  const [state, setState] = useState({ loading: false, paths: null, error: null });
  // The finding currently shown in the slide-in detail panel.
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Build an id → finding lookup once so AttackPathCard can resolve nodes.
  const findingById = useMemo(() => {
    const map = {};
    findings.forEach(f => { map[f.id] = f; });
    return map;
  }, [findings]);

  // Fetch attack paths every time this component mounts (i.e. every time the
  // user clicks the Attack Paths tab, since we unmount on tab switch).
  useEffect(() => {
    if (findings.length === 0) return;
    setState({ loading: true, paths: null, error: null });
    fetchAttackPaths(findings)
      .then(data => setState({ loading: false, paths: data.attack_paths ?? [], error: null }))
      .catch(err  => setState({ loading: false, paths: null, error: err.message }));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  // Intentionally empty deps — we want this to run once on mount, not re-run
  // if findings reference identity changes. The parent re-mounts on tab switch.

  const handleNodeClick = (step) => {
    const finding = findingById[step.finding_id];
    if (finding) setSelectedFinding(finding);
  };

  return (
    <div className={styles.wrapper}>

      {/* ── Loading state ─────────────────────────────────────── */}
      {state.loading && (
        <div className={styles.loadingWrap}>
          <div className={styles.loadingPulse} />
          <div className={styles.loadingText}>
            <p className={styles.loadingHeadline}>Analyzing attack paths across your AWS environment</p>
            <p className={styles.loadingSubline}>Chaining your findings into realistic attack scenarios…</p>
          </div>
        </div>
      )}

      {/* ── Error state ───────────────────────────────────────── */}
      {state.error && (
        <div className={styles.errorBox}>
          <span className={styles.errorIcon}>!</span>
          <p>{state.error}</p>
        </div>
      )}

      {/* ── No findings ───────────────────────────────────────── */}
      {!state.loading && !state.error && findings.length === 0 && (
        <div className={styles.empty}>
          Run a scan first to generate attack path analysis.
        </div>
      )}

      {/* ── Attack path cards ─────────────────────────────────── */}
      {state.paths && state.paths.length === 0 && (
        <div className={styles.empty}>
          No chained attack paths identified — your account posture looks strong.
        </div>
      )}

      {state.paths && state.paths.map(path => (
        <AttackPathCard
          key={path.id}
          path={path}
          findingById={findingById}
          onNodeClick={handleNodeClick}
        />
      ))}

      {/* ── MITRE ATT&CK legend ───────────────────────────────── */}
      {!state.loading && (
        <div className={styles.legendCard}>
          <h3 className={styles.legendTitle}>MITRE ATT&CK Tactics Reference</h3>
          <div className={styles.legendGrid}>
            {MITRE_TACTICS.map(t => (
              <div key={t.name} className={styles.legendItem}>
                <span className={styles.legendDot} style={{ background: t.color }} />
                <span className={styles.legendLabel}>{t.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Finding detail modal — same component used in the findings table */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}

// AttackPathCard renders a single attack path: goal header, SVG graph, narrative.
function AttackPathCard({ path, findingById, onNodeClick }) {
  const sev = path.severity?.toLowerCase();
  const isCritical = sev === 'critical';

  return (
    <div className={`${styles.pathCard} ${isCritical ? styles.pathCardCritical : ''}`}>

      {/* ── Card header ─────────────────────────────────────── */}
      <div className={styles.cardHeader}>
        <div className={styles.cardHeaderLeft}>
          <h2 className={styles.goalText}>{path.goal}</h2>
        </div>
        <div className={styles.cardHeaderRight}>
          <SeverityBadge severity={sev} size="md" />
          {path.mitre_tactics?.length > 0 && (
            <div className={styles.tacticPills}>
              {path.mitre_tactics.map(t => (
                <span key={t} className={styles.tacticPill}>{t}</span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── SVG graph ───────────────────────────────────────── */}
      <div className={styles.graphWrap}>
        <AttackGraph
          steps={path.steps}
          pathId={path.id}
          onNodeClick={onNodeClick}
          findingById={findingById}
        />
      </div>

      {/* ── Narrative ───────────────────────────────────────── */}
      <p className={styles.narrative}>{path.narrative}</p>

      <p className={styles.clickHint}>Click any node to view the full finding details</p>
    </div>
  );
}
