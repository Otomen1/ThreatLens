"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { getWorkspaceStartSummary, type WorkspaceStartSummary } from "@/lib/api/workspace";
import { getFeedHome, type FeedItem } from "@/lib/api/threatFeed";
import { useSessionIdentity } from "@/hooks/useSessionIdentity";
import { LoadingRows } from "@/components/ui/Skeleton";
export function StartPanel() {
  const owner = useSessionIdentity();
  const [personal, setPersonal] = useState<{ owner: string; data: WorkspaceStartSummary } | null>(null);
  const [news, setNews] = useState<FeedItem[] | null>(null);
  const [privateError, setPrivateError] = useState(false);
  const [feedError, setFeedError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    void getFeedHome({ limit_per_region: 3 }, { signal: controller.signal }).then((r) => { if (!r.sections) throw new Error("Invalid feed response"); if (!controller.signal.aborted) { setNews(Object.values(r.sections).flatMap((s) => s.items).sort((a, b) => b.published_at.localeCompare(a.published_at)).slice(0, 3)); setFeedError(false); } }).catch(() => { if (!controller.signal.aborted) setFeedError(true); });
    return () => controller.abort();
  }, [attempt]);
  useEffect(() => {
    setPersonal(null); setPrivateError(false);
    if (!owner) return;
    const controller = new AbortController();
    void getWorkspaceStartSummary(controller.signal).then((data) => { if (!Array.isArray(data.recent)) throw new Error("Invalid start response"); if (!controller.signal.aborted) setPersonal({ owner, data }); }).catch(() => { if (!controller.signal.aborted) setPrivateError(true); });
    return () => controller.abort();
  }, [owner, attempt]);
  const data = personal?.owner === owner ? personal.data : null;
  return <section aria-label="Start here" className="space-y-4 rounded-2xl border border-zinc-800 bg-zinc-900/50 p-5 text-sm">
    <h2 className="font-medium text-white">Start here</h2>
    {!owner ? <p className="text-zinc-400"><Link href="/login" className="underline">Sign in</Link> to continue saved work. Searching never saves an investigation automatically.</p> : data ? <>
      <p className="text-xs text-zinc-400">{data.investigations ?? "Unavailable"} investigations · {data.draft_detections ?? "Unavailable"} draft rules · {data.open_cases ?? "Unavailable"} open cases</p>
      <ul className="space-y-2">{data.recent.map((r) => <li key={r.id}><Link className="text-sky-300 hover:underline focus-visible:outline" href={`/workspace/${encodeURIComponent(r.id)}`}>Continue: {r.title}</Link></li>)}</ul>
      {!data.recent.length && data.availability.workspace && <p className="text-zinc-500">No saved work yet. Search an indicator, then choose Save.</p>}
      {Object.entries(data.availability).filter(([, available]) => !available).map(([name]) => <p key={name} className="text-amber-300">{name} information unavailable; searching is unaffected.</p>)}
      {data.provider_issues.map((issue) => <p key={issue.provider} className="text-amber-300">{issue.provider}: {issue.code.replaceAll("_", " ")} · <Link href="/dashboard">Diagnostics</Link></p>)}
    </> : privateError ? <p role="status">Saved-work overview unavailable.</p> : <LoadingRows rows={2} label="Loading saved work" />}
    <h3 className="text-zinc-300">Recent threat reports</h3>
    {news ? <ul className="space-y-2">{news.map((item) => <li key={item.id}><Link className="text-zinc-400 hover:text-sky-300 focus-visible:outline" href={`/threat-feed/${encodeURIComponent(item.id)}`}>{item.title}</Link></li>)}{!news.length && <li className="text-zinc-500">No collected reports yet.</li>}</ul> : feedError ? <p>Feed highlights unavailable.</p> : <LoadingRows rows={2} label="Loading feed highlights" />}
    {(privateError || feedError) && <button className="text-sky-300 underline" onClick={() => setAttempt((a) => a + 1)}>Retry start panel</button>}
  </section>;
}
