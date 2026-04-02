import { useState, useCallback } from 'react';
import { useSummary }      from './hooks/useSummary';
import { useScan }         from './hooks/useScan';
import SeveritySummaryBar from './components/SeveritySummaryBar/SeveritySummaryBar';
import ComplianceCards    from './components/ComplianceCards/ComplianceCards';
import FindingsTable      from './components/FindingsTable/FindingsTable';
import AttackPaths        from './components/AttackPaths/AttackPaths';
import styles from './App.module.css';

const REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-central-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
  'ca-central-1', 'sa-east-1',
];

const EMPTY_FORM = {
  accessKeyId:     '',
  secretAccessKey: '',
  sessionToken:    '',
  region:          'us-east-1',
};

export default function App() {
  const summary = useSummary();
  const scan    = useScan();

  const [scanned,    setScanned]    = useState(false);
  const [savedCreds, setSavedCreds] = useState(null);
  const [form,       setForm]       = useState(EMPTY_FORM);
  const [activeTab,  setActiveTab]  = useState('findings');

  const findings   = scan.data?.findings ?? [];
  const isScanning = scan.loading || summary.loading;

  const toCreds = (f) => ({
    access_key_id:     f.accessKeyId,
    secret_access_key: f.secretAccessKey,
    session_token:     f.sessionToken,
    region:            f.region,
  });

  const handleFormChange = (e) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const handleScanSubmit = useCallback((e) => {
    e.preventDefault();
    const creds = toCreds(form);
    setSavedCreds(creds);
    setScanned(true);
    setActiveTab('findings');
    summary.run(creds);
    scan.run(creds);
  }, [form, summary, scan]);

  const handleRescan = useCallback(() => {
    if (!savedCreds) return;
    setActiveTab('findings');
    summary.run(savedCreds);
    scan.run(savedCreds);
  }, [savedCreds, summary, scan]);

  const handleChangeKeys = () => setScanned(false);

  const canSubmit = form.accessKeyId.trim() !== '' && form.secretAccessKey.trim() !== '';

  // ── Landing / credential form ─────────────────────────────────
  if (!scanned) {
    return (
      <div className={styles.layout}>
        <div className={styles.landing}>
          <div className={styles.landingCard}>
            <h1 className={styles.landingTitle}>CSPM Dashboard</h1>
            <p className={styles.landingDesc}>
              Enter your AWS credentials to scan your account against CIS
              benchmark controls across S3, IAM, EC2, and CloudTrail.
            </p>

            <form className={styles.credForm} onSubmit={handleScanSubmit}>
              <div className={styles.formRow}>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel} htmlFor="accessKeyId">
                    Access Key ID
                  </label>
                  <input
                    id="accessKeyId"
                    name="accessKeyId"
                    type="text"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="AKIAIOSFODNN7EXAMPLE"
                    className={styles.formInput}
                    value={form.accessKeyId}
                    onChange={handleFormChange}
                    required
                  />
                </div>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel} htmlFor="secretAccessKey">
                    Secret Access Key
                  </label>
                  <input
                    id="secretAccessKey"
                    name="secretAccessKey"
                    type="password"
                    autoComplete="new-password"
                    placeholder="••••••••••••••••••••••••"
                    className={styles.formInput}
                    value={form.secretAccessKey}
                    onChange={handleFormChange}
                    required
                  />
                </div>
              </div>

              <div className={styles.formGroup}>
                <label className={styles.formLabel} htmlFor="region">Region</label>
                <select
                  id="region"
                  name="region"
                  className={styles.formSelect}
                  value={form.region}
                  onChange={handleFormChange}
                >
                  {REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>

              <div className={styles.formGroup}>
                <label className={styles.formLabel} htmlFor="sessionToken">
                  Session Token{' '}
                  <span className={styles.formOptional}>optional</span>
                </label>
                <input
                  id="sessionToken"
                  name="sessionToken"
                  type="password"
                  autoComplete="new-password"
                  placeholder="For temporary / MFA credentials"
                  className={styles.formInput}
                  value={form.sessionToken}
                  onChange={handleFormChange}
                />
              </div>

              <button type="submit" className={styles.scanBtn} disabled={!canSubmit}>
                Run Security Scan
              </button>
            </form>

            <p className={styles.landingHint}>
              Credentials are sent directly to your local backend and never stored.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ── Dashboard ─────────────────────────────────────────────────
  return (
    <div className={styles.layout}>
      <header className={styles.header}>
        <div className={styles.brand}>
          <div>
            <h1 className={styles.brandName}>CSPM Dashboard</h1>
            <p className={styles.brandSub}>Cloud Security Posture Management</p>
          </div>
        </div>

        <div className={styles.headerRight}>
          <SeveritySummaryBar
            summary={summary.data}
            loading={summary.loading}
            error={summary.error}
          />
          <div className={styles.headerActions}>
            <button
              className={styles.rescanBtn}
              onClick={handleRescan}
              disabled={isScanning}
              title="Re-run the scan with the same credentials"
            >
              {isScanning ? 'Scanning…' : '↺ Re-scan'}
            </button>
            <button
              className={styles.changeCredsBtn}
              onClick={handleChangeKeys}
              disabled={isScanning}
              title="Enter different AWS credentials"
            >
              ← Change Keys
            </button>
          </div>
        </div>
      </header>

      {/* ── Tab bar ─────────────────────────────────────────────── */}
      <nav className={styles.tabBar}>
        <button
          className={`${styles.tab} ${activeTab === 'findings' ? styles.tabActive : ''}`}
          onClick={() => setActiveTab('findings')}
        >
          Findings
          {!scan.loading && findings.length > 0 && (
            <span className={styles.tabCount}>{findings.length}</span>
          )}
        </button>
        <button
          className={`${styles.tab} ${activeTab === 'attack-paths' ? styles.tabActive : ''}`}
          onClick={() => setActiveTab('attack-paths')}
          disabled={scan.loading || findings.length === 0}
          title={scan.loading ? 'Waiting for scan to complete…' : ''}
        >
          Attack Paths
          <span className={styles.tabBeta}>AI</span>
        </button>
      </nav>

      <main className={styles.main}>
        {activeTab === 'findings' && (
          <>
            <section className={styles.section}>
              <h2 className={styles.sectionTitle}>Compliance by Service</h2>
              <p className={styles.sectionSub}>Security posture across each scanned AWS service</p>
              <ComplianceCards findings={findings} loading={scan.loading} error={scan.error} />
            </section>

            <section className={styles.section}>
              <h2 className={styles.sectionTitle}>All Findings</h2>
              <p className={styles.sectionSub}>
                {scan.loading
                  ? 'Running live AWS scan — this may take up to a minute…'
                  : `${findings.length} total findings across your AWS account`}
              </p>
              <FindingsTable findings={findings} loading={scan.loading} error={scan.error} />
            </section>
          </>
        )}

        {activeTab === 'attack-paths' && (
          <section className={styles.section}>
            <h2 className={styles.sectionTitle}>Attack Path Analysis</h2>
            <p className={styles.sectionSub}>
              AI-identified chains of misconfigurations an attacker could exploit in sequence
            </p>
            {/* Unmount/remount on each tab visit so analysis always re-runs */}
            <AttackPaths key={scan.data?.scanned_at} findings={findings} />
          </section>
        )}
      </main>
    </div>
  );
}
