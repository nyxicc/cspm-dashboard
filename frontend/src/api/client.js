// Base URL is empty in development (Vite proxy forwards /api/* to :8080).
// Set VITE_API_BASE in .env.local if deploying the frontend separately.
const BASE = import.meta.env.VITE_API_BASE ?? '';

// post sends a JSON POST and returns the parsed body.
// Throws an Error with the server's own error message when the response is not OK.
async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error ?? `HTTP ${res.status}`);
  }
  return res.json();
}

// fetchSummary POSTs credentials to /api/findings/summary.
export const fetchSummary = (creds) => post('/api/findings/summary', creds);

// fetchScan POSTs credentials to /api/scan.
export const fetchScan = (creds) => post('/api/scan', creds);

// fetchExplain POSTs a finding to /api/explain and returns { explanation }.
export const fetchExplain = (finding) => post('/api/explain', finding);

// fetchAttackPaths POSTs the findings array to /api/attack-paths and returns
// { attack_paths: [...] }.
export const fetchAttackPaths = (findings) => post('/api/attack-paths', { findings });
