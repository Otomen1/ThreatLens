"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useFeedParams, useFeedReady } from "./FeedPanelContext";
import { ActionToolbar } from "@/components/ui/ActionToolbar";
import { ThreatFeedSection } from "@/components/threat-feed/ThreatFeedSection";
import {
  getFeedHome,
  refreshFeed,
  getFeedItems,
  type FeedHomeParams,
  type FeedHomeResponse,
  type FeedRegion,
} from "@/lib/api/threatFeed";
import { readFeedHomeCache, writeFeedHomeCache } from "@/lib/threatFeedCache";
import { useToast } from "@/components/ui/ToastProvider";
import { SearchLoading } from "@/components/ui/SearchLoading";

const regions: FeedRegion[] = ["global", "malaysia", "southeast_asia"];
const topics = ["advisory", "vulnerability", "active_exploitation", "phishing", "ransomware", "malware", "breach", "supply_chain", "threat_actor", "scam", "research"];

function FeedSkeleton() {
  return <div className="space-y-6">
    <SearchLoading label="Loading threat feed…" />
    <div aria-hidden="true" className="space-y-6 animate-pulse">
    <div className="grid gap-3 sm:grid-cols-3">{[0, 1, 2].map((value) => <div key={value} className="h-24 rounded-xl border border-zinc-800 bg-zinc-900" />)}</div>
    <div className="h-20 rounded-2xl border border-zinc-800 bg-zinc-900" />
    {[0, 1, 2].map((section) => <div key={section} className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60"><div className="h-12 border-b border-zinc-800 bg-zinc-900"/><div className="space-y-px">{[0, 1, 2, 3, 4].map((row) => <div key={row} className="h-12 bg-zinc-900/70" />)}</div></div>)}
    </div>
  </div>;
}

export default function NewsFeed() {
  const params = useFeedParams();
  const router = useRouter();
  const { notify } = useToast();
  const [data, setData] = useState<FeedHomeResponse | null>(null);
  const query = params.get("query") ?? "";
  const topic = params.get("topic") ?? "";
  const sort = params.get("sort") ?? "newest";
  const hours = ["24", "168", "720"].includes(params.get("hours") ?? "") ? params.get("hours")! : "168";
  const region = regions.find((value) => value === params.get("region"));
  const page = Math.max(1, Number(params.get("page")) || 1);
  const update = (key: string, value: string) => {
    const next = new URLSearchParams(params.toString());
    value ? next.set(key, value) : next.delete(key);
    if (key !== "page") next.delete("page");
    router.replace(`/threat-feed?${next}`, { scroll: false });
  };
  const setQuery = (value: string) => update("query", value);
  const setTopic = (value: string) => update("topic", value);
  const setHours = (value: string) => update("hours", value);
  const [status, setStatus] = useState("Loading threat feed…");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  useFeedReady(Boolean(data) || !loading);
  const requestRef = useRef(0);
  const dataRef = useRef<FeedHomeResponse | null>(null);

  const load = useCallback(async (fresh = false) => {
    const params: FeedHomeParams = { query, topic, hours: Number(hours), limit_per_region: 5, sort };
    const requestId = ++requestRef.current;
    setLoading(true);
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
      if (region) {
        const listing = await getFeedItems({ region, query, topic, hours: Number(hours), page, page_size: 20, sort });
        response.sections[region] = { items: listing.items, total: listing.total };
      }
      if (requestRef.current !== requestId) return;
      dataRef.current = response;
      setData(response);
      if (!region) writeFeedHomeCache(params, response);
      setStatus("");
    } catch {
      if (requestRef.current !== requestId) return;
      setStatus(cached || dataRef.current ? "Could not update the feed. Showing the last available reports." : "The feed is temporarily unavailable. Try again shortly.");
    } finally {
      if (requestRef.current === requestId) setLoading(false);
    }
  }, [hours, query, topic, region, page, sort]);

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
        notify("Threat Feed refresh is cooling down.", "warning");
      } else {
        await load(true);
        setStatus(`${result.items_added} new items collected.`);
        notify(`Threat Feed updated: ${result.items_added} new item${result.items_added === 1 ? "" : "s"}.`);
      }
    } catch {
      setStatus("Refresh could not be started. Existing reports are unchanged.");
      notify("Threat Feed refresh failed; existing reports were kept.", "error");
    } finally {
      setBusy(false);
    }
  }

  return <main className="min-h-screen px-4 py-10"><div className="mx-auto max-w-6xl space-y-6">
    <ActionToolbar context={<p className="max-w-2xl text-sm text-zinc-500">Cybersecurity reporting and official advisories, routed by regional relevance. Source-reported entities remain unverified until investigated.</p>}><button disabled={busy} onClick={() => void refresh()} className="rounded-lg border border-sky-500/30 px-4 py-2 text-sm text-sky-300 hover:bg-sky-500/10 disabled:opacity-50">{busy ? "Refreshing…" : "Refresh feed"}</button></ActionToolbar>
    {!data ? loading ? <FeedSkeleton /> : <div role="alert" className="rounded-xl border border-zinc-800 p-6 text-sm text-zinc-400"><p>{status}</p><button onClick={() => void load()} className="mt-3 rounded-lg border border-zinc-700 px-3 py-2">Retry loading feed</button></div> : <>
      <section key={data.generated_at} className="animate-data-pulse grid gap-3 rounded-xl sm:grid-cols-3"><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">New in 24 hours</p><p className="mt-1 text-2xl font-semibold">{Object.values(data.summary.regions).reduce((sum, value) => sum + value.recent, 0)}</p></div><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">Source-reported entities</p><p className="mt-1 text-2xl font-semibold">{data.summary.new_iocs}</p></div><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">Last refresh</p><p className="mt-2 text-sm text-zinc-200">{data.summary.last_refreshed_at ? new Date(data.summary.last_refreshed_at).toLocaleString() : "Not refreshed yet"}</p></div></section>
      <section className="grid gap-3 rounded-2xl border border-zinc-800 bg-zinc-900 p-4 md:grid-cols-[1fr_180px_160px]"><input aria-label="Search threat feed" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search titles, summaries, sources…" className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-sky-500"/><select aria-label="Topic" value={topic} onChange={(event) => setTopic(event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="">All topics</option>{topics.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select><select aria-label="Time range" value={hours} onChange={(event) => setHours(event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select></section>
      {status ? <p role="status" aria-live="polite" className="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-sm text-zinc-400">{status}</p> : null}
      {(region ? [region] : regions).map((value) => <ThreatFeedSection key={value} region={value} items={data.sections[value].items} total={data.sections[value].total}/>)}
      {region && <div className="flex items-center justify-between text-sm"><button disabled={page <= 1} onClick={() => update("page", String(page - 1))}>Previous</button><span>Page {page}</span><button disabled={page * 20 >= data.sections[region].total} onClick={() => update("page", String(page + 1))}>Next</button></div>}
      </>}
  </div></main>;
}
