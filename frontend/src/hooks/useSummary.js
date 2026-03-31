import { useState, useCallback } from 'react';
import { fetchSummary } from '../api/client';

// useSummary does NOT auto-run. Call run(creds) with AWS credentials to fetch
// the severity summary.
export function useSummary() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const run = useCallback((creds) => {
    setLoading(true);
    setError(null);
    fetchSummary(creds)
      .then(d  => setData(d))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return { data, loading, error, run };
}
