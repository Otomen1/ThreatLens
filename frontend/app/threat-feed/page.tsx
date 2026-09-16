"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ThreatFeedSection } from "@/components/threat-feed/ThreatFeedSection";
import {
  getFeedHome,
  refreshFeed,
  type FeedHomeParams,
  type FeedHomeResponse,
  type FeedRegion,
} from "@/lib/api/threatFeed";
import { readFeedHomeCache, writeFeedHomeCache } from "@/lib/threatFeedCache";

const regions: FeedRegion[] = ["global", "malaysia", "southeast_asia"];
const topics = ["advisory", "vulnerability", "active_exploitation", "phishing", "ransomware", "malware", "breach", "supply_chain", "threat_actor", "scam", "research"];

function FeedSkeleton() {
  return <div aria-label="Loading threat feed" role="status" className="space-y-6 animate-pulse">
    <div className="grid gap-3 sm:grid-cols-3">{[0, 1, 2].map((value) => <div key={value} className="h-24 rounded-xl border border-zinc-800 bg-zinc-900" />)}</div>
    <div className="h-20 rounded-2xl border border-zinc-800 bg-zinc-900" />
    {[0, 1, 2].map((section) => <div key={section} className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60"><div className="h-12 border-b border-zinc-800 bg-zinc-900"/><div className="space-y-px">{[0, 1, 2, 3, 4].map((row) => <div key={row} className="h-12 bg-zinc-900/70" />)}</div></div>)}
    <span className="sr-only">Loading threat reports</span>
  </div>;
}

export default function ThreatFeedPage() {
  const [data, setData] = useState<FeedHomeResponse | null>(null);
  const [query, setQuery] = useState("");
  const [topic, setTopic] = useState("");
  const [hours, setHours] = useState("168");
  const [status, setStatus] = useState("Loading threat feed…");
  const [busy, setBusy] = useState(false);
  const requestRef = useRef(0);
  const dataRef = useRef<FeedHomeResponse | null>(null);

  const load = useCallback(async (fresh = false) => {
    const params: FeedHomeParams = { query, topic, hours: Number(hours), limit_per_region: 5 };
    const requestId = ++requestRef.current;
    const cached = fresh ? null : readFeedHomeCache(params);
    if (cached) {
      dataRef.current = cached.response;
      setData(cached.response);
      setStatus(cached.freshness === "fresh" ? "Showing cached reports while checking for updates…" : "Showing older reports while reconnecting…");
    } else if (dataRef.current) {
      setStatus("Updating reports…");
    } else {
      setStatus("Loading threat feed…");
    }
    try {
      const response = await getFeedHome(params, { fresh });
      if (requestRef.current !== requestId) return;
      dataRef.current = response;
      setData(response);
      writeFeedHomeCache(params, response);
      setStatus("");
    } catch {
      if (requestRef.current !== requestId) return;
      setStatus(cached || dataRef.current ? "Could not update the feed. Showing the last available reports." : "The feed is temporarily unavailable. Try again shortly.");
    }
  }, [hours, query, topic]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 250);
    return () => window.clearTimeout(timer);
  }, [load]);

  async function refresh() {
    setBusy(true);
    setStatus("Refreshing sources… Current reports remain available.");
    try {
      const result = await refreshFeed();
      if (result.status === "cooldown") {
        setStatus("Refresh is cooling down. Existing reports are still current.");
      } else {
        await load(true);
        setStatus(`${result.items_added} new items collected.`);
      }
    } catch {
      setStatus("Refresh could not be started. Existing reports are unchanged.");
    } finally {
      setBusy(false);
    }
  }

  return <main className="min-h-screen px-4 py-10"><div className="mx-auto max-w-6xl space-y-6">
    <header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-xs uppercase tracking-[0.18em] text-sky-400">Source-attributed intelligence</p><h1 className="mt-2 text-3xl font-semibold">Threat Feed</h1><p className="mt-2 max-w-2xl text-sm text-zinc-500">Cybersecurity reporting and official advisories, routed by regional relevance. Source-reported entities remain unverified until investigated.</p></div><button disabled={busy} onClick={() => void refresh()} className="rounded-lg border border-sky-500/30 px-4 py-2 text-sm text-sky-300 hover:bg-sky-500/10 disabled:opacity-50">{busy ? "Refreshing…" : "Refresh feed"}</button></header>
    {!data ? <FeedSkeleton /> : <>
      <section className="grid gap-3 sm:grid-cols-3"><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">New in 24 hours</p><p className="mt-1 text-2xl font-semibold">{Object.values(data.summary.regions).reduce((sum, value) => sum + value.recent, 0)}</p></div><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">Source-reported entities</p><p className="mt-1 text-2xl font-semibold">{data.summary.new_iocs}</p></div><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">Last refresh</p><p className="mt-2 text-sm text-zinc-200">{data.summary.last_refreshed_at ? new Date(data.summary.last_refreshed_at).toLocaleString() : "Not refreshed yet"}</p></div></section>
      <section className="grid gap-3 rounded-2xl border border-zinc-800 bg-zinc-900 p-4 md:grid-cols-[1fr_180px_160px]"><input aria-label="Search threat feed" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search titles, summaries, sources…" className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-sky-500"/><select aria-label="Topic" value={topic} onChange={(event) => setTopic(event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="">All topics</option>{topics.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select><select aria-label="Time range" value={hours} onChange={(event) => setHours(event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select></section>
      {status ? <p role="status" aria-live="polite" className="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-sm text-zinc-400">{status}</p> : null}
      {regions.map((region) => <ThreatFeedSection key={region} region={region} items={data.sections[region].items} total={data.sections[region].total}/>)}</>}
  </div></main>;
}
