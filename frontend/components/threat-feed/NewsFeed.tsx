"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useFeedParams, useFeedReady } from "./FeedPanelContext";
import { ActionToolbar } from "@/components/ui/ActionToolbar";
import { NewsTable } from "./NewsTable";
import { refreshFeed, type FeedRegion } from "@/lib/api/threatFeed";
import { useToast } from "@/components/ui/ToastProvider";
import { SearchLoading } from "@/components/ui/SearchLoading";
import { FeedTableControls } from "./FeedExperience";
import { useNewsFeedData } from "@/hooks/useNewsFeedData";
import { NEWS_PAGE_SIZE, NEWS_REGIONS, NEWS_REGION_DETAILS, NEWS_TOPICS, latestNews, newsHref } from "@/lib/newsFeed";
import { clearNewsRegionCache } from "@/lib/newsRegionCache";
import { markRegionSeen } from "@/lib/threatFeedState";

function FeedSkeleton({ regional }: { regional: boolean }) {
  return <div className="space-y-6">
    <SearchLoading label="Loading threat feed…" />
    <div aria-hidden="true" className="space-y-6 animate-pulse">
      {!regional && <div className="grid gap-3 sm:grid-cols-3">{[0, 1, 2].map((value) => <div key={value} className="h-24 rounded-xl border border-zinc-800 bg-zinc-900" />)}</div>}
      <div className="h-20 rounded-2xl border border-zinc-800 bg-zinc-900" />
      <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60"><div className="h-12 border-b border-zinc-800 bg-zinc-900" /><div className="space-y-px">{Array.from({ length: 10 }, (_, row) => <div key={row} className="h-12 bg-zinc-900/70" />)}</div></div>
    </div>
  </div>;
}

function NewsFilters({ query, topic, hours, update }: { query: string; topic: string; hours: string; update: (key: string, value: string) => void }) {
  return <div className="grid gap-3 rounded-2xl border border-zinc-800 bg-zinc-900 p-4 md:grid-cols-[1fr_180px_160px]">
    <input aria-label="Search threat feed" value={query} onChange={(event) => update("query", event.target.value)} placeholder="Search titles, summaries, sources…" className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-sky-500" />
    <select aria-label="Topic" value={topic} onChange={(event) => update("topic", event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="">All topics</option>{NEWS_TOPICS.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select>
    <select aria-label="Time range" value={hours} onChange={(event) => update("hours", event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select>
  </div>;
}

export default function NewsFeed({ region }: { region?: FeedRegion }) {
  const params = useFeedParams();
  const router = useRouter();
  const { notify } = useToast();
  const query = params.get("query") ?? "";
  const topic = NEWS_TOPICS.includes(params.get("topic") ?? "") ? params.get("topic")! : "";
  const sort = region && params.get("sort") === "oldest" ? "oldest" : "newest";
  const hours = ["24", "168", "720"].includes(params.get("hours") ?? "") ? params.get("hours")! : "168";
  const page = Math.min(10000, Math.max(1, Math.floor(Number(params.get("page")) || 1)));
  const { home, listing, loading, status, setStatus, load, previousFilters } = useNewsFeedData(region, query, topic, Number(hours), page, sort);
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  const viewKey = JSON.stringify({ region, query, topic, hours, page, sort });
  const currentView = useRef(viewKey);
  useEffect(() => { currentView.current = viewKey; }, [viewKey]);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { if (region && listing) markRegionSeen(region); }, [region, listing]);
  const ready = Boolean(home || listing);
  useFeedReady(ready || !loading);
  const update = (key: string, value: string) => {
    const next = new URLSearchParams(params.toString());
    value ? next.set(key, value) : next.delete(key);
    if (key !== "page") next.delete("page");
    router.replace(newsHref(region, next, true), { scroll: false });
  };
  async function refresh() {
    const refreshingView = currentView.current;
    setBusy(true); setStatus("Refreshing sources… Current reports remain available.");
    try {
      const result = await refreshFeed();
      if (!mounted.current || refreshingView !== currentView.current) return;
      if (result.status === "cooldown") {
        setStatus("Refresh is cooling down. Existing reports remain available.");
        notify("Threat Feed refresh is cooling down.", "warning");
      } else if (result.status === "failed") {
        setStatus("Sources could not be refreshed. Existing reports are unchanged.");
        notify("Threat Feed sources are unavailable; existing reports were kept.", "warning");
      } else {
        clearNewsRegionCache();
        const updated = await load(true);
        if (mounted.current && updated && refreshingView === currentView.current) {
          setStatus(`${result.items_added} new items collected.`);
          notify(`Threat Feed updated: ${result.items_added} new item${result.items_added === 1 ? "" : "s"}.`);
        }
      }
    } catch {
      if (mounted.current && refreshingView === currentView.current) { setStatus("Refresh could not be started. Existing reports are unchanged."); notify("Threat Feed refresh failed; existing reports were kept.", "error"); }
    } finally { if (mounted.current) setBusy(false); }
  }
  const title = region ? `${NEWS_REGION_DETAILS[region].label} reports` : "Latest 10 news";
  const items = region ? listing?.items ?? [] : home ? latestNews(home) : [];
  const total = region ? listing?.total ?? 0 : home ? NEWS_REGIONS.reduce((count, value) => count + home.sections[value].total, 0) : 0;
  const displayedPage = listing?.page ?? page;
  return <main data-list-ready={ready} className="min-h-screen px-4 py-10"><div className="mx-auto max-w-6xl space-y-6">
    {region && <div className="space-y-3"><Link className="text-sm text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={newsHref(undefined, params)}>← Back to News</Link><h2 className="text-2xl font-semibold">{NEWS_REGION_DETAILS[region].label} news</h2><p className="text-sm text-zinc-500">10 reports per page. Regional placement is not proof of targeting.</p></div>}
    <ActionToolbar context={<p className="max-w-2xl text-sm text-zinc-500">Cybersecurity reporting and official advisories, routed by regional relevance. Source-reported entities remain unverified until investigated.</p>}><button disabled={busy} onClick={() => void refresh()} className="rounded-lg border border-sky-500/30 px-4 py-2 text-sm text-sky-300 hover:bg-sky-500/10 disabled:opacity-50">{busy ? "Refreshing…" : "Refresh feed"}</button></ActionToolbar>
    {!ready ? loading ? <FeedSkeleton regional={Boolean(region)} /> : <div role="alert" className="rounded-xl border border-zinc-800 p-6 text-sm text-zinc-400"><p>{status}</p><button onClick={() => void load()} className="mt-3 rounded-lg border border-zinc-700 px-3 py-2">Retry loading feed</button></div> : <>
      {home && <section key={home.generated_at} aria-label="News activity" className="animate-data-pulse grid gap-3 rounded-xl sm:grid-cols-3"><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">New in 24 hours</p><p className="mt-1 text-2xl font-semibold">{Object.values(home.summary.regions).reduce((sum, value) => sum + value.recent, 0)}</p></div><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">Source-reported entities</p><p className="mt-1 text-2xl font-semibold">{home.summary.new_iocs}</p></div><div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"><p className="text-xs text-zinc-500">Last refresh</p><p className="mt-2 text-sm text-zinc-200">{home.summary.last_refreshed_at ? new Date(home.summary.last_refreshed_at).toLocaleString() : "Not refreshed yet"}</p></div></section>}
      <section className="space-y-4" aria-label="News listing">
        <NewsFilters query={query} topic={topic} hours={hours} update={update} />
        <p role="status" aria-live="polite" className="min-h-5 text-sm text-zinc-400">{previousFilters && "Previous filter results · "}{status}</p>
        {!loading && status.startsWith("Could not update") && <button className="rounded-lg border border-zinc-700 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-sky-400" onClick={() => void load()}>Retry loading feed</button>}
        <FeedTableControls table="news" />
        <NewsTable title={title} items={items} total={total} offset={region ? (displayedPage - 1) * NEWS_PAGE_SIZE : 0} />
      </section>
      {home && <section aria-labelledby="browse-news-regions" className="space-y-3"><h2 id="browse-news-regions" className="text-lg font-semibold">Browse by region</h2><div className="grid gap-3 md:grid-cols-3">{NEWS_REGIONS.map((value) => <Link key={value} href={newsHref(value, params)} className="group rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-sky-500/50 focus-visible:outline focus-visible:outline-sky-400"><div className="flex items-center justify-between gap-3"><h3 className="font-medium"><span aria-hidden="true" className="mr-2 text-sky-400">{NEWS_REGION_DETAILS[value].icon}</span>{NEWS_REGION_DETAILS[value].label}</h3><span aria-hidden="true" className="text-sky-400">→</span></div><p className="mt-2 text-xs text-zinc-400">{home.sections[value].total} matching reports</p><p className="mt-3 text-xs text-sky-300">Browse news</p></Link>)}</div></section>}
      {region && <nav aria-label="Regional news pagination" className="flex flex-wrap items-center justify-between gap-3 text-sm"><button className="rounded-lg border border-zinc-700 px-3 py-2 focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40" disabled={page <= 1 || loading} onClick={() => update("page", String(page - 1))}>Previous</button><span>Page {page} of {Math.max(1, Math.ceil(total / NEWS_PAGE_SIZE))}</span><button className="rounded-lg border border-zinc-700 px-3 py-2 focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40" disabled={page * NEWS_PAGE_SIZE >= total || loading} onClick={() => update("page", String(page + 1))}>Next</button></nav>}
    </>}
  </div></main>;
}
