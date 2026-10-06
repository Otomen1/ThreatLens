"use client";
import { useEffect, useState } from "react";

/** Independent saved-data reads; retries are always explicit and keep previous data. */
export function useRetryableResource<T>(load: () => Promise<T>, initial: T) {
  const [data, setData] = useState(initial);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    setLoading(true);
    void load().then((value) => { if (active) { setData(value); setError(false); } })
      .catch(() => { if (active) setError(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [load, attempt]);
  return { data, setData, loading, error, retry: () => setAttempt((value) => value + 1) };
}
