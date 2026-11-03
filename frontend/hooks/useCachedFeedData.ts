"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "@/lib/api/client";
import type { CachedFeed } from "@/lib/publicFeedCache";

type Options<T> = {
  key: string; scope: string;
  search?: string;
  read: () => CachedFeed<T> | null;
  fetch: (fresh: boolean, signal: AbortSignal) => Promise<T>;
  valid: (value: unknown) => value is T;
  write: (value: T) => void;
};
export function useCachedFeedData<T>(options: Options<T>) {
  const [current, setCurrent] = useState<{ data: T; key: string; scope: string } | null>(null);
  const [status, setStatus] = useState("Loading saved feed data…");
  const [loading, setLoading] = useState(true);
  const [slow, setSlow] = useState(false);
  const previous = useRef<typeof current>(null);
  const request = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const slowTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const retryAt = useRef(0);
  const priorSearch = useRef(options.search);
  const cancel = useCallback(() => {
    request.current++; controller.current?.abort(); clearTimeout(slowTimer.current);
  }, []);
  const load = useCallback(async (fresh = false) => {
    cancel();
    const id = request.current;
    const abort = new AbortController(); controller.current = abort;
    const cached = fresh ? null : options.read();
    const typing = priorSearch.current !== options.search;
    priorSearch.current = options.search;
    setSlow(false);
    if (cached) {
      const value = { data: cached.response, key: options.key, scope: options.scope };
      previous.current = value; setCurrent(value);
      setStatus(cached.freshness === "fresh" ? "Showing cached data · collected source dates are shown separately." : "Showing older cached data while checking for updates…");
      if (cached.freshness === "fresh") { setLoading(false); return true; }
    } else setStatus(previous.current?.scope === options.scope ? "Updating saved data… Previous results remain visible." : "Loading saved feed data…");
    if (retryAt.current > Date.now()) {
      setStatus(`Loading is cooling down. Retry after ${new Date(retryAt.current).toLocaleTimeString()}. Previous results are unchanged.`);
      setLoading(false); return false;
    }
    setLoading(true);
    slowTimer.current = setTimeout(() => { if (request.current === id) setSlow(true); }, 4000);
    try {
      if (!fresh && typing) await new Promise<void>((resolve, reject) => {
        const stop = () => { clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")); };
        const timer = setTimeout(() => { abort.signal.removeEventListener("abort", stop); resolve(); }, 200);
        abort.signal.addEventListener("abort", stop, { once: true });
        if (abort.signal.aborted) stop();
      });
      const response = await options.fetch(fresh, abort.signal);
      if (request.current !== id || abort.signal.aborted) return false;
      if (!options.valid(response)) throw new ApiError("The saved feed response was incomplete. Previous results are unchanged.", 502);
      const value = { data: response, key: options.key, scope: options.scope };
      options.write(response); previous.current = value; setCurrent(value); setStatus(""); retryAt.current = 0;
      return true;
    } catch (error) {
      if (request.current !== id || abort.signal.aborted) return false;
      if (error instanceof ApiError) retryAt.current = error.retryAt ?? 0;
      const reason = error instanceof ApiError && error.status === 408 ? "Loading saved data timed out." : error instanceof ApiError && error.status === 429 ? "Loading is rate-limited. Wait before retrying." : "Could not update the feed.";
      setStatus(`${reason} ${previous.current?.scope === options.scope ? "Showing the last available reports." : "No saved data is available yet."}`);
      return false;
    } finally {
      if (request.current === id) { clearTimeout(slowTimer.current); setLoading(false); setSlow(false); }
    }
  }, [options, cancel]);
  useEffect(() => { void load(); return cancel; }, [load, cancel]);
  const visible = current?.scope === options.scope ? current : null;
  return { data: visible?.data ?? null, loading, slow, status, setStatus, load, previousFilters: Boolean(visible && visible.key !== options.key) };
}
