"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { getFeedActivity, type FeedActivity } from "@/lib/api/threatFeed";
import { ACTIVITY_KINDS, finishFeedVisit, isFeedActivity, startFeedVisit, type FeedVisit } from "@/lib/feedVisit";
import { vendors } from "@/lib/api/iocReports";

const groups = {
  news: { label: "News published", href: "/threat-feed" },
  vulnerability: { label: "Vulnerability activity", href: "/threat-feed?tab=vulnerabilities" },
  ioc: { label: "IOC report activity", href: "/threat-feed?tab=iocs" },
};
const control = "rounded-lg border border-zinc-700 px-3 py-2 text-xs focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40";
export function FeedBrief() {
  const visit = useRef<FeedVisit | null>(null);
  const [data, setData] = useState<FeedActivity | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [localWarning, setLocalWarning] = useState(false);
  const [caughtUp, setCaughtUp] = useState(false);
  useEffect(() => {
    visit.current ??= startFeedVisit();
    const baseline = visit.current.baseline;
    const controller = new AbortController();
    setLoading(true);
    void getFeedActivity(baseline, controller.signal, attempt > 0).then((result) => {
      if (controller.signal.aborted) return;
      if (!isFeedActivity(result)) throw new Error("Brief unavailable");
      setData(result); setError(false); setCaughtUp(false);
      const saved = finishFeedVisit(visit.current!, result.generated_at);
      visit.current = saved.visit; setLocalWarning(!saved.persisted);
    }).catch(() => { if (!controller.signal.aborted) setError(true); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [attempt]);
  function acknowledge() {
    if (!data || !visit.current) return;
    const saved = finishFeedVisit(visit.current, data.generated_at, true);
    visit.current = saved.visit; setLocalWarning(!saved.persisted); setCaughtUp(true);
    setData({ ...data, since: data.generated_at, window_start: data.generated_at, limited: false,
      groups: { news: { total: 0, items: [] }, vulnerability: { total: 0, items: [] }, ioc: { total: 0, items: [] } } });
  }
  return <section aria-labelledby="feed-visit-heading" className="feed-brief rounded-xl border border-zinc-800 bg-zinc-900/40 px-4 py-3">
    <div className="flex flex-wrap items-center gap-3"><header className="flex flex-wrap items-center gap-x-5 gap-y-2"><h2 id="feed-visit-heading" className="text-sm font-semibold">Since your last visit</h2>
      {data?.since && <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">{ACTIVITY_KINDS.map((kind) => <span key={kind} aria-label={`${groups[kind].label}: ${data.groups[kind].total}`}>{kind === "news" ? "News" : kind === "vulnerability" ? "Vulnerabilities" : "IOC reports"} <strong className="ml-1 tabular-nums text-zinc-100">{data.groups[kind].total}</strong></span>)}</div>}
    </header>
    <details className="feed-brief-details ml-auto text-xs text-zinc-400"><summary className="feed-interactive w-fit cursor-pointer rounded py-1 text-sky-300 focus-visible:outline focus-visible:outline-sky-400">Brief details</summary>
      <div className="mt-3 flex flex-wrap gap-2"><button className={control} disabled={loading} onClick={() => setAttempt((value) => value + 1)}>{loading ? "Checking brief…" : error ? "Retry activity brief" : "Check for updates"}</button>{data?.since && <button className={control} disabled={loading || caughtUp} onClick={acknowledge}>Mark caught up</button>}</div>
      <p className="mt-3">Browser-local visit times · Stored feed activity across all sources, independent of News filters.</p>
      {data?.since && <p className="mt-2">Activity after {new Date(data.window_start).toLocaleString()}. Checked {new Date(data.generated_at).toLocaleString()}.</p>}
      {data?.since && <div className="mt-4 grid gap-4 sm:grid-cols-3">{ACTIVITY_KINDS.map((kind) => <section key={kind} className="min-w-0"><h3 className="font-medium text-zinc-200">{groups[kind].label}</h3>{data.groups[kind].items.length ? <ul className="mt-2 space-y-3">{data.groups[kind].items.map((item) => <li key={item.id}><Link className="break-words text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={item.href}>{item.title}</Link><p className="mt-1 text-zinc-400">{kind === "ioc" ? vendors[item.source as keyof typeof vendors] ?? item.source : item.source} · {new Date(item.activity_at).toLocaleString()}</p></li>)}</ul> : <p className="mt-2">No stored activity in this interval.</p>}<Link className="mt-3 inline-block text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={groups[kind].href}>Browse {kind === "news" ? "News" : kind === "vulnerability" ? "Vulnerabilities" : "IOC Reports"}</Link></section>)}</div>}
      <p className="mt-3">Up to three recent items per category. News uses publication dates; vulnerabilities and IOC reports use source-record activity dates, not collection time or unread counts. Delayed collection may add older reports. Available metadata is not complete coverage. No providers are queried.</p>
    </details></div>
    <p role="status" aria-live="polite" className={!error && !loading && !caughtUp && data?.since ? "sr-only" : "mt-2 text-xs text-zinc-400"}>{error ? `${data ? "Previous brief retained. " : ""}Activity could not load; News is still available. Your visit baseline has not advanced.` : loading ? data ? "Updating the brief; previous counts remain visible." : "Loading stored activity…" : caughtUp ? "Caught up as of the checked time. Article read state and bookmarks are unchanged." : data?.since ? `Activity after ${new Date(data.window_start).toLocaleString()}. Checked ${new Date(data.generated_at).toLocaleString()}.` : "First visit: your baseline is ready. Future visits can show activity since this check."}</p>
    {data?.limited && <p className="mt-2 text-xs text-amber-200">Your previous visit is older than the retained window. Only the latest 30 days are included.</p>}
    {localWarning && <p className="mt-2 text-xs text-amber-200">Visit history could not be saved in this browser. The brief still works for this open view.</p>}
  </section>;
}
