"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useFeedParams, useFeedReady } from "./FeedPanelContext";
import { NewsTable } from "./NewsTable";
import { refreshFeed, type FeedRegion, type FeedSourceOption } from "@/lib/api/threatFeed";
import { useToast } from "@/components/ui/ToastProvider";
import { SearchLoading } from "@/components/ui/SearchLoading";
import { FeedToolbar } from "./FeedToolbar";
import { useNewsFeedData } from "@/hooks/useNewsFeedData";
import { NEWS_PAGE_SIZE, NEWS_REGIONS, NEWS_REGION_DETAILS, NEWS_TOPICS, latestNews, newsHref, validNewsSource } from "@/lib/newsFeed";
import { clearNewsRegionCache } from "@/lib/newsRegionCache";
import { markRegionSeen } from "@/lib/threatFeedState";
import { useFeedSelection } from "@/hooks/useFeedSelection";
import { FeedBulkActions } from "./FeedBulkActions";
import { FeedBrief } from "./FeedBrief";
import { FeedStats, FeedNotice, FeedRefreshHelp } from "./FeedUi";
import { FeedDate } from "./FeedExperience";

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

function NewsFilters({ query, topic, source, sources, hours, update }: { query: string; topic: string; source: string; sources: FeedSourceOption[]; hours: string; update: (key: string, value: string) => void }) {
  return <div className="grid grid-cols-2 gap-3 xl:grid-cols-[minmax(180px,1fr)_160px_180px_130px]">
    <input aria-label="Search threat feed" value={query} onChange={(event) => update("query", event.target.value)} placeholder="Search news titles, summaries, or sources…" className="col-span-2 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-sky-500 md:col-span-1" />
    <select aria-label="Topic" value={topic} onChange={(event) => update("topic", event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="">All topics</option>{NEWS_TOPICS.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select>
    <select aria-label="News source" value={source} onChange={(event) => update("source", event.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"><option value="">All sources</option>{source && !sources.some((item) => item.id === source) && <option value={source}>Current source: {source}</option>}{sources.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
    <select aria-label="Time range" value={hours} onChange={(event) => update("hours", event.target.value)} className="col-span-2 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm md:col-span-1"><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select>
  </div>;
}

export default function NewsFeed({ region }: { region?: FeedRegion }) {
  const params = useFeedParams();
  const router = useRouter();
  const { notify } = useToast();
  const query = params.get("query") ?? "";
  const source = validNewsSource(params.get("source"));
  const topic = NEWS_TOPICS.includes(params.get("topic") ?? "") ? params.get("topic")! : "";
  const sort = region && params.get("sort") === "oldest" ? "oldest" : "newest";
  const hours = ["24", "168", "720"].includes(params.get("hours") ?? "") ? params.get("hours")! : "168";
  const page = Math.min(10000, Math.max(1, Math.floor(Number(params.get("page")) || 1)));
  const { home, listing, loading, slow, status, setStatus, load, previousFilters } = useNewsFeedData(region, query, topic, Number(hours), page, sort, source);
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  const viewKey = JSON.stringify({ region, query, topic, source, hours, page, sort });
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
        setStatus(`Refresh is cooling down. Existing reports remain available.${result.next_refresh_at ? ` Next eligible: ${new Date(result.next_refresh_at).toLocaleString()}.` : ""}`);
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
  const selection = useFeedSelection(viewKey, items);
  const selectionPaused = loading || previousFilters;
  const actions = <><button disabled={busy || loading} onClick={() => void load(true)} className="feed-control feed-control-primary">Reload saved data</button><button disabled={busy} onClick={() => void refresh()} className="feed-control">{busy ? "Refreshing sources…" : "Refresh sources"}</button></>;
  return <main data-list-ready={ready} className="feed-page min-h-screen px-4"><div className="mx-auto max-w-6xl space-y-5">
    {region && <div className="space-y-3"><Link className="text-sm text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={newsHref(undefined, params)}>← Back to News</Link><h2 className="text-2xl font-semibold">{NEWS_REGION_DETAILS[region].label} news</h2><p className="text-sm text-zinc-500">10 reports per page. Regional placement is not proof of targeting.</p></div>}
    {!ready && slow && <p role="status" className="text-sm text-zinc-400">Loading is taking longer than usual. This read will stop after 12 seconds.</p>}
    {!ready ? loading ? <FeedSkeleton regional={Boolean(region)} /> : <div role="alert" className="rounded-xl border border-zinc-800 p-6 text-sm text-zinc-400"><p>{status}</p><button onClick={() => void load()} className="mt-3 rounded-lg border border-zinc-700 px-3 py-2">Retry loading feed</button></div> : <>
      {home && <FeedStats label="News activity" items={[{ label: "New in 24 hours", value: Object.values(home.summary.regions).reduce((sum, value) => sum + value.recent, 0) }, { label: "Source-reported entities", value: home.summary.new_iocs }, { label: "Last refresh", value: home.summary.last_refreshed_at ? <FeedDate value={home.summary.last_refreshed_at} relative /> : "Not refreshed yet", compact: true }]} />}
      <section className="space-y-4" aria-label="News listing">
        {home && <FeedBrief />}
        <FeedToolbar table="news" region={region} actions={actions}><NewsFilters query={query} topic={topic} source={source} sources={home?.source_options ?? listing?.source_options ?? []} hours={hours} update={update} /></FeedToolbar>
        <FeedRefreshHelp />
        {home && source && <p className="text-xs text-zinc-500">Activity cards cover all sources; reports below match your selected publisher.</p>}
        <FeedNotice warning={/Could not|failed|timed out|cooling|rate-limited/.test(status)}>{status || previousFilters ? <>{previousFilters && "Previous filter results · "}{status}{slow && " This is taking longer than usual. Loading will stop after 12 seconds."}</> : null}</FeedNotice>
        {!loading && /Could not|timed out|rate-limited/.test(status) && <button className="rounded-lg border border-zinc-700 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-sky-400" onClick={() => void load(true)}>Retry loading feed</button>}
        <FeedBulkActions key={viewKey} kind="news" items={items} selection={selection} disabled={selectionPaused} />
        <NewsTable title={title} items={items} total={total} showRegion={!region} offset={region ? (displayedPage - 1) * NEWS_PAGE_SIZE : 0} rowSelection={{ selection, disabled: selectionPaused }} />
      </section>
      {home && <section aria-labelledby="browse-news-regions" className="space-y-3"><h2 id="browse-news-regions" className="text-lg font-semibold">Browse by region</h2><div className="grid gap-3 md:grid-cols-3">{NEWS_REGIONS.map((value) => <Link key={value} href={newsHref(value, params)} className="group rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-sky-500/50 focus-visible:outline focus-visible:outline-sky-400"><div className="flex items-center justify-between gap-3"><h3 className="font-medium"><span aria-hidden="true" className="mr-2 text-sky-400">{NEWS_REGION_DETAILS[value].icon}</span>{NEWS_REGION_DETAILS[value].label}</h3><span aria-hidden="true" className="text-sky-400">→</span></div><p className="mt-2 text-xs text-zinc-400">{home.sections[value].total} matching reports</p><p className="mt-3 text-xs text-sky-300">Browse news</p></Link>)}</div></section>}
      {region && <nav aria-label="Regional news pagination" className="feed-pagination"><button className="feed-control" disabled={page <= 1 || loading} onClick={() => update("page", String(page - 1))}>Previous</button><span>Page {page} of {Math.max(1, Math.ceil(total / NEWS_PAGE_SIZE))}</span><button className="feed-control" disabled={page * NEWS_PAGE_SIZE >= total || loading} onClick={() => update("page", String(page + 1))}>Next</button></nav>}
    </>}
  </div></main>;
}
