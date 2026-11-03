"use client";

import Link from "next/link";
import { TargetingBadge } from "@/components/threat-feed/FeedFilters";
import { IocChanges } from "@/components/threat-feed/IocChanges";
import { BookmarkButton } from "@/components/threat-feed/SavedFeed";
import { AddToCase } from "@/components/threat-feed/AddToCase";
import { RelatedIntelligence } from "@/components/threat-feed/FeedWorkflow";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { getIocReport, iocTypes, vendors, type IocDetail } from "@/lib/api/iocReports";
import { defang, downloadIocs, localReportState } from "@/lib/iocReports";
import { markFeedRead } from "@/lib/feedDisplay";
import { CopyButton } from "@/components/ui/CopyButton";
import { LoadingRows } from "@/components/ui/Skeleton";
import { useToast } from "@/components/ui/ToastProvider";
import { FeedDate } from "@/components/threat-feed/FeedExperience";
import { FeedBadge } from "@/components/threat-feed/FeedBadge";

const control = "feed-control";
export default function IocReportDetail() {
  const { id } = useParams<{ id: string }>(); const { notify } = useToast();
  const [data, setData] = useState<IocDetail | null>(null); const [error, setError] = useState("");
  const [query, setQuery] = useState(""); const [kind, setKind] = useState(""); const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set()); const [attempt, setAttempt] = useState(0);
  useEffect(() => { const controller = new AbortController(); setData(null); setSelected(new Set()); setError(""); void getIocReport(id, controller.signal).then((value) => { if (controller.signal.aborted) return; setData(value); localReportState("read", id); markFeedRead("ioc", id); }).catch(() => { if (!controller.signal.aborted) setError("IOC report unavailable. Try again; collection never runs just by opening a report."); }); return () => controller.abort(); }, [id, attempt]);
  const filtered = useMemo(() => (data?.indicators ?? []).filter((i) => (!kind || i.type === kind) && (!query || i.value.toLowerCase().includes(query.toLowerCase()) || defang(i.value).toLowerCase().includes(query.toLowerCase()))), [data, kind, query]);
  const rows = filtered.slice((page - 1) * 20, page * 20);
  const chosen = data?.indicators.filter((i) => selected.has(i.id)) ?? [];
  function toggle(value: string) { setSelected((old) => { const next = new Set(old); next.has(value) ? next.delete(value) : next.add(value); return next; }); }
  function exportRows(format: "json" | "csv", all = false) { if (!data) return; downloadIocs(data.report, all ? data.indicators : chosen, format); notify(`${all ? "All" : "Selected"} indicators exported as ${format.toUpperCase()}.`); }
  return <main className="feed-detail min-h-screen space-y-5">
    <Link href="/threat-feed?tab=iocs" className="text-sm text-sky-300">← IOC Reports</Link>
    {error ? <div role="alert" className="rounded-xl border border-red-900 p-4">{error}<button className={`${control} ml-3`} onClick={() => setAttempt((n) => n + 1)}>Retry</button></div> : !data ? <LoadingRows rows={5} label="Loading IOC report" /> : <>
      <header className="feed-detail-header"><div className="mb-3 flex flex-wrap gap-2"><FeedBadge>IOC Report</FeedBadge>{data.report.withdrawn && <FeedBadge tone="high">Withdrawn</FeedBadge>}</div><h1>{data.report.title}</h1><p className="mt-3 text-sm text-zinc-400">{vendors[data.report.vendor as keyof typeof vendors]} · {data.indicators.length} indicators · Updated <FeedDate value={data.report.activity_at} /></p><div className="feed-detail-actions"><a href={data.report.source_url} target="_blank" rel="noreferrer" className={`${control} feed-control-primary`}>Official source file ↗</a>{data.report.article_url && <a href={data.report.article_url} target="_blank" rel="noreferrer" className={control}>Original report ↗</a>}<BookmarkButton kind="ioc" id={id} title={data.report.title} /></div></header>
      <div className="feed-detail-grid"><div className="feed-detail-body"><section className="feed-detail-panel text-xs leading-6 text-amber-200"><h2 className="mb-2 text-zinc-200">Report context</h2><p>Source-reported · Not independently verified · Current activity unknown. Indicators are not automatically blocked, scanned, or investigated.</p>{data.report.warnings.map((warning) => <p className="mt-2" key={warning}>{warning}</p>)}</section><AddToCase kind="ioc" id={data.report.id} /><TargetingBadge evidence={data.report.targeting_evidence} /></div><aside className="feed-detail-facts" aria-label="IOC report facts"><section className="feed-detail-panel"><h2>Source provenance</h2><dl className="mt-4 space-y-3 text-xs text-zinc-400"><div><dt>Published</dt><dd className="mt-1 text-zinc-200"><FeedDate value={data.report.published_at} /></dd></div><div><dt>Collected</dt><dd className="mt-1 text-zinc-200"><FeedDate value={data.report.collected_at} /></dd></div><div><dt>Source file</dt><dd className="mt-1 break-all text-zinc-200">{data.report.path}</dd></div><div><dt>Parser / commit</dt><dd className="mt-1 font-mono text-zinc-200">{data.report.parser_version} · {data.report.commit.slice(0, 12)}</dd></div></dl></section></aside></div>
      <div className="feed-toolbar flex flex-wrap gap-3 rounded-xl border border-zinc-800 p-4"><input aria-label="Search report indicators" className={`${control} min-w-0 w-full basis-full sm:basis-auto sm:flex-1`} placeholder="Search indicators…" value={query} onChange={(e) => { setQuery(e.target.value); setPage(1); }} /><select aria-label="Report IOC type" className={control} value={kind} onChange={(e) => { setKind(e.target.value); setPage(1); }}><option value="">All types</option>{iocTypes.map((type) => <option key={type}>{type}</option>)}</select><button className={control} onClick={() => setSelected((old) => new Set([...old, ...rows.map((i) => i.id)]))}>Select current page</button><button className={control} onClick={() => setSelected(new Set())}>Clear selection</button></div>
      <div data-pinned-header className="sticky top-16 z-10 ui-action-toolbar rounded-xl border border-zinc-800 bg-zinc-950 p-3"><span className="self-center text-xs text-zinc-400">{chosen.length} selected</span><div className="ui-toolbar-actions"><CopyButton value={chosen.map((i) => defang(i.value)).join("\n")} label="Copy selected (defanged)" className={control} /><CopyButton value={chosen.map((i) => i.value).join("\n")} label="Copy selected (normalized)" className={control} /><button className={control} disabled={!chosen.length} onClick={() => exportRows("json")}>Export selected JSON</button><button className={control} disabled={!chosen.length} onClick={() => exportRows("csv")}>Export selected CSV</button><button className={control} onClick={() => exportRows("json", true)}>Export all JSON</button><button className={control} onClick={() => exportRows("csv", true)}>Export all CSV</button>{chosen.length > 0 && chosen.length <= 20 && <Link className={control} href={`/?q=${encodeURIComponent(chosen.map((i) => i.value).join("\n"))}`}>Prepare selected investigation</Link>}{chosen.length > 20 && <span className="text-xs text-amber-300">Select at most 20 for batch investigation.</span>}</div></div>
      <div role="table" aria-label="Report indicators" className="space-y-2">{rows.map((item) => <div role="row" key={item.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-zinc-800 p-3"><div role="cell"><input type="checkbox" aria-label={`Select ${item.value}`} checked={selected.has(item.id)} onChange={() => toggle(item.id)} /></div><div role="cell" className="text-xs text-zinc-500">{item.type}</div><div role="cell" className="min-w-0 flex-1 break-all font-mono text-xs">{defang(item.value)}</div><div role="cell" className="flex gap-2"><CopyButton value={defang(item.value)} className={control} /><Link className={control} href={`/?q=${encodeURIComponent(item.value)}`}>Investigate</Link></div></div>)}</div>
      {!filtered.length && <p className="text-sm text-zinc-500">No indicators match these filters.</p>}
      <nav aria-label="Report indicator pagination" className="feed-pagination"><button className={control} disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page} · {filtered.length} indicators</span><button className={control} disabled={page * 20 >= filtered.length} onClick={() => setPage(page + 1)}>Next</button></nav>
      <footer className="text-xs text-zinc-500">{data.report.attribution} · <a className="text-sky-300" href={data.report.license_url} target="_blank" rel="noreferrer">{data.report.license}</a>. Exports retain attribution and required notices.</footer>
      <IocChanges report={data.report} />
      <RelatedIntelligence kind="ioc" id={id} />
    </>}
  </main>;
}
