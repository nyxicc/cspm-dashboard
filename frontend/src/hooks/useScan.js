import { useState, useCallback } from 'react';
import { fetchScan } from '../api/client';

// useScan does NOT auto-run. Call run(creds) with AWS credentials to trigger
// a live scan. Expect 10–60 seconds of loading time on real accounts.
export function useScan() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const run = useCallback((creds) => {
    setLoading(true);
    setError(null);
    fetchScan(creds)
      .then(d  => setData(d))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return { data, loading, error, run };
}
