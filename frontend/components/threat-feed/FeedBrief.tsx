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
  return <section aria-labelledby="feed-visit-heading" className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
    <header className="flex flex-wrap items-center justify-between gap-3"><div><h2 id="feed-visit-heading" className="text-sm font-semibold">Since your last visit</h2><p className="mt-1 text-xs text-zinc-500">Browser-local visit times · Stored feed activity across all sources, independent of News filters.</p></div><div className="flex flex-wrap gap-2"><button className={control} disabled={loading} onClick={() => setAttempt((value) => value + 1)}>{loading ? "Checking brief…" : error ? "Retry activity brief" : "Check for updates"}</button>{data?.since && <button className={control} disabled={loading || caughtUp} onClick={acknowledge}>Mark caught up</button>}</div></header>
    <p role="status" aria-live="polite" className="mt-3 text-xs text-zinc-400">{error ? `${data ? "Previous brief retained. " : ""}Activity could not load; News is still available. Your visit baseline has not advanced.` : loading ? data ? "Updating the brief; previous counts remain visible." : "Loading stored activity…" : caughtUp ? "Caught up as of the checked time. Article read state and bookmarks are unchanged." : data?.since ? `Activity after ${new Date(data.window_start).toLocaleString()}. Checked ${new Date(data.generated_at).toLocaleString()}.` : "First visit: your baseline is ready. Future visits can show activity since this check."}</p>
    {data?.since && <><div className="mt-3 grid gap-3 sm:grid-cols-3">{ACTIVITY_KINDS.map((kind) => <div key={kind} className="min-w-0 rounded-lg border border-zinc-800 p-3"><h3 className="text-xs text-zinc-400">{groups[kind].label}</h3><p className="mt-1 text-xl font-semibold tabular-nums" aria-label={`${groups[kind].label}: ${data.groups[kind].total}`}>{data.groups[kind].total}</p><Link className="mt-2 inline-block text-xs text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={groups[kind].href}>Browse {kind === "news" ? "News" : kind === "vulnerability" ? "Vulnerabilities" : "IOC Reports"}</Link></div>)}</div>
      <details className="mt-3 text-xs text-zinc-400"><summary className="cursor-pointer focus-visible:outline focus-visible:outline-sky-400">Recent activity · Up to three per category</summary><div className="mt-3 grid gap-4 sm:grid-cols-3">{ACTIVITY_KINDS.map((kind) => <section key={kind} className="min-w-0"><h3 className="font-medium text-zinc-200">{groups[kind].label}</h3>{data.groups[kind].items.length ? <ul className="mt-2 space-y-3">{data.groups[kind].items.map((item) => <li key={item.id}><Link className="break-words text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={item.href}>{item.title}</Link><p className="mt-1 text-zinc-500">{kind === "ioc" ? vendors[item.source as keyof typeof vendors] ?? item.source : item.source} · {new Date(item.activity_at).toLocaleString()}</p></li>)}</ul> : <p className="mt-2 text-zinc-500">No stored activity in this interval.</p>}</section>)}</div></details></>}
    {data?.limited && <p className="mt-3 text-xs text-amber-200">Your previous visit is older than the retained window. Only the latest 30 days are included.</p>}
    {localWarning && <p className="mt-3 text-xs text-amber-200">Visit history could not be saved in this browser. The brief still works for this open view.</p>}
    <p className="mt-3 text-xs text-zinc-500">News uses publication dates; vulnerabilities and IOC reports use source-record activity dates, not collection time or unread counts. Delayed collection may add older reports. Available metadata is not complete coverage. No providers are queried.</p>
  </section>;
}
