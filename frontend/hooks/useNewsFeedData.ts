"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { getFeedHome, getFeedItems, type FeedHomeResponse, type FeedList, type FeedRegion } from "@/lib/api/threatFeed";
import { readFeedHomeCache, writeFeedHomeCache } from "@/lib/threatFeedCache";
import { readNewsRegionCache, writeNewsRegionCache } from "@/lib/newsRegionCache";

type Data = { scope: string; key: string; home?: FeedHomeResponse; listing?: FeedList };
function delay(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => { window.clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")); };
    const timer = window.setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, 200);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

export function useNewsFeedData(region: FeedRegion | undefined, query: string, topic: string, hours: number, page: number, sort: string) {
  const scope = region ?? "home";
  const key = JSON.stringify({ scope, query, topic, hours, page: region ? page : 1, sort: region ? sort : "newest" });
  const [data, setData] = useState<Data | null>(null);
  const [status, setStatus] = useState("Loading threat feed…");
  const [loading, setLoading] = useState(true);
  const previous = useRef<Data | null>(null);
  const requestId = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const load = useCallback(async (fresh = false) => {
    const active = ++requestId.current;
    controller.current?.abort();
    const abort = new AbortController(); controller.current = abort;
    const homeParams = { query, topic, hours, limit_per_region: 10, sort: "newest" };
    const cached = fresh ? null : region ? readNewsRegionCache(key) : readFeedHomeCache(homeParams);
    setLoading(true);
    if (cached) {
      const value: Data = { scope, key, ...(region ? { listing: cached.response as FeedList } : { home: cached.response as FeedHomeResponse }) };
      previous.current = value; setData(value);
      setStatus(cached.freshness === "fresh" ? "Showing cached reports while checking for updates…" : "Showing older reports while reconnecting…");
    } else if (previous.current?.scope === scope) setStatus("Updating reports… Previous results remain visible.");
    else { setData(null); setStatus("Loading threat feed…"); }
    try {
      if (!fresh) await delay(abort.signal);
      let value: Data;
      if (region) {
        const listing = await getFeedItems({ region, query, topic, hours, page, page_size: 10, sort }, { signal: abort.signal, fresh });
        value = { scope, key, listing };
      } else {
        const home = await getFeedHome(homeParams, { signal: abort.signal, fresh });
        value = { scope, key, home };
      }
      if (active !== requestId.current || abort.signal.aborted) return;
      if (value.listing) writeNewsRegionCache(key, value.listing);
      if (value.home) writeFeedHomeCache(homeParams, value.home);
      previous.current = value; setData(value); setStatus("");
      return true;
    } catch {
      if (active !== requestId.current || abort.signal.aborted) return;
      setStatus(previous.current?.scope === scope ? "Could not update the feed. Showing the last available reports." : "The feed is temporarily unavailable. Try again shortly.");
      return false;
    } finally { if (active === requestId.current) setLoading(false); }
  }, [region, query, topic, hours, page, sort, scope, key]);
  const cancel = useCallback(() => { requestId.current++; controller.current?.abort(); }, []);
  useEffect(() => {
    void load();
    return cancel;
  }, [load, cancel]);
  const visible = data?.scope === scope ? data : null;
  return { home: visible?.home ?? null, listing: visible?.listing ?? null, loading, status, setStatus, load, previousFilters: Boolean(visible && visible.key !== key) };
}
