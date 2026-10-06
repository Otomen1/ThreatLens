"use client";
import Link from "next/link";
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { get } from "@/lib/api/client";
import { type FeedItem, type Vulnerability } from "@/lib/api/threatFeed";
import { type IocDetail, vendors } from "@/lib/api/iocReports";
import { defang } from "@/lib/iocReports";
import { bookmarkPath, type SavedKind } from "@/lib/feedBookmarks";
import { markFeedRead } from "@/lib/feedDisplay";
import { BookmarkButton } from "./SavedFeed";
import { FeedDate } from "./FeedExperience";
import { TargetingBadge } from "./FeedFilters";

type Selection = { kind: SavedKind; id: string; title: string };
const PreviewContext = createContext<(selection: Selection) => void>(() => undefined);
export function PreviewButton({ kind, id, title }: Selection) {
  const open = useContext(PreviewContext);
  return <button type="button" aria-label={`Preview ${title}`} className="mt-1 rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-400 hover:text-sky-300" onClick={() => open({ kind, id, title })}>Preview</button>;
}
function sourceLink(value?: string | null) {
  try { const url = new URL(value ?? ""); return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password ? url.href : null; }
  catch { return null; }
}
export function FeedPreviewProvider({ children }: { children: ReactNode }) {
  const [opened, setOpened] = useState<{ selection: Selection; trigger: HTMLElement | null } | null>(null);
  function open(selection: Selection) { setOpened({ selection, trigger: document.activeElement as HTMLElement | null }); }
  return <PreviewContext.Provider value={open}>{children}{opened && <PreviewDrawer key={`${opened.selection.kind}:${opened.selection.id}`} selection={opened.selection} close={() => setOpened(null)} trigger={opened.trigger} />}</PreviewContext.Provider>;
}
function PreviewDrawer({ selection, close, trigger }: { selection: Selection; close: () => void; trigger: HTMLElement | null }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const [data, setData] = useState<FeedItem | Vulnerability | IocDetail | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const node = dialog.current;
    node?.showModal(); closeButton.current?.focus();
    const root = document.documentElement;
    const overflow = root.style.overflow, gutter = root.style.scrollbarGutter;
    root.style.scrollbarGutter = "stable"; root.style.overflow = "hidden";
    return () => { node?.close(); root.style.overflow = overflow; root.style.scrollbarGutter = gutter; if (trigger?.isConnected) trigger.focus({ preventScroll: true }); };
  }, [trigger]);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(false);
    const endpoint = selection.kind === "news" ? "items" : selection.kind === "ioc" ? "ioc-reports" : "vulnerabilities";
    void get<FeedItem | Vulnerability | IocDetail>(`/threat-feed/${endpoint}/${encodeURIComponent(selection.id)}`, controller.signal)
      .then((record) => {
        if (controller.signal.aborted) return;
        if (!record || !("title" in record || "report" in record)) throw new Error("Unavailable metadata");
        setData(record); markFeedRead(selection.kind, selection.id);
      }).catch(() => { if (!controller.signal.aborted) setError(true); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [selection.kind, selection.id, attempt]);
  const news = data && "summary" in data ? data : null;
  const vulnerability = data && "scores" in data ? data : null;
  const ioc = data && "report" in data ? data : null;
  const title = news?.title ?? vulnerability?.title ?? ioc?.report.title ?? selection.title;
  const url = sourceLink(news?.url ?? ioc?.report.article_url ?? ioc?.report.source_url ?? vulnerability?.references[0]);
  return <dialog ref={dialog} className="feed-preview m-0 ml-auto h-dvh max-h-none w-full max-w-xl border-l border-zinc-700 bg-zinc-950 p-0 text-zinc-200 backdrop:bg-black/50" aria-labelledby="preview-title" onCancel={(event) => { event.preventDefault(); close(); }} onClick={(event) => { if (event.target === event.currentTarget) close(); }} onKeyDown={(event) => {
    if (event.key !== "Tab") return;
    const controls = [...event.currentTarget.querySelectorAll<HTMLElement>('a[href],button:not(:disabled),input:not(:disabled),select:not(:disabled),[tabindex="0"]')].filter((node) => node.getClientRects().length > 0);
    const first = controls[0], last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }}>
    <article className="min-h-full space-y-5 p-5 sm:p-6">
      <header className="flex items-start justify-between gap-4"><div><p className="text-xs text-zinc-500">Stored feed preview · No investigation runs</p><h2 id="preview-title" className="mt-2 break-words text-xl font-semibold">{title}</h2></div><button ref={closeButton} type="button" aria-label="Close preview" className="rounded border border-zinc-700 px-3 py-2 text-sm" onClick={close}>Close</button></header>
      <div className="flex flex-wrap gap-3"><Link className="rounded border border-sky-800 px-3 py-2 text-sm text-sky-300" href={bookmarkPath(selection.kind, selection.id)} onClick={close}>Open full details</Link><BookmarkButton kind={selection.kind} id={selection.id} title={title} />{url && <a className="px-3 py-2 text-sm text-sky-300" href={url} target="_blank" rel="noreferrer">Read at source ↗</a>}</div>
      <p role="status" className="text-sm text-zinc-400">{loading ? "Loading stored metadata…" : error ? "Couldn't load this preview. It may be unavailable or expired." : ""}</p>
      {error && !loading && <button className="rounded border border-zinc-700 px-3 py-2 text-sm" onClick={() => setAttempt((n) => n + 1)}>Retry preview</button>}
      {news && <><p className="text-xs text-zinc-500">{news.source_name} · <FeedDate value={news.published_at} relative /> · {news.topic.replaceAll("_", " ")}</p><p className="whitespace-pre-line text-sm leading-6">{news.summary}</p><TargetingBadge evidence={news.targeting_evidence} /><h3 className="font-medium">Section placement</h3><ul className="list-inside list-disc text-sm text-zinc-400">{news.region_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul><p className="text-xs text-zinc-500">Source-reported entities are unverified; full details provide explicit investigation actions.</p></>}
      {vulnerability && <><p className="text-xs text-zinc-500">{vulnerability.cve_id ?? "CVE not assigned"} · {vulnerability.sources.join(", ")}</p><p className="whitespace-pre-line text-sm leading-6">{vulnerability.description}</p><p className="text-sm">Affected products: {vulnerability.products.join(", ") || "Not supplied"}</p><p className="text-sm">Severity: {vulnerability.severity ?? "Not rated"}</p>{vulnerability.scores.map((score) => <p key={`${score.source}:${score.version}`} className="text-xs text-zinc-400">{score.source} · CVSS {score.version}: {score.score}</p>)}<p className="text-sm text-amber-200">{[vulnerability.reported_zero_day ? "Reported zero-day" : "", vulnerability.known_exploited ? "Known exploited" : ""].filter(Boolean).join(" · ") || "Exploitation not reported"}</p><TargetingBadge evidence={vulnerability.targeting_evidence} /></>}
      {ioc && <><p className="text-xs text-zinc-500">{vendors[ioc.report.vendor as keyof typeof vendors] ?? ioc.report.vendor} · {ioc.report.indicator_count} indicators</p><p className="break-all text-xs text-zinc-500">{ioc.report.path}</p><p className="text-xs text-zinc-500">Updated: <FeedDate value={ioc.report.activity_at} relative /></p><TargetingBadge evidence={ioc.report.targeting_evidence} /><p className="text-sm text-amber-200">Source-reported and unverified{ioc.report.withdrawn ? " · Report withdrawn" : ""}</p><ul className="space-y-2">{ioc.indicators.slice(0, 10).map((indicator) => <li key={indicator.id} className="break-all font-mono text-xs">{indicator.type}: {defang(indicator.value)}</li>)}</ul>{ioc.indicators.length > 10 && <p className="text-xs text-zinc-500">First 10 shown. Open full details for the complete list and attributed export.</p>}<p className="text-xs text-zinc-500">{ioc.report.attribution} · {ioc.report.license}</p></>}
    </article>
  </dialog>;
}
