"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { InvestigationWorkspace } from "@/components/InvestigationWorkspace";
import { saveInvestigation, type BatchPreviewResponse } from "@/lib/api";
import { detectionEligible, downloadText, providerCounts, riskLabel, rowsToCsv } from "@/lib/batch";
import { entityLabel } from "@/lib/investigation";
import type { BatchRow } from "@/hooks/useBatchInvestigation";

interface Props {
  preview: BatchPreviewResponse;
  rows: BatchRow[];
  setRows: React.Dispatch<React.SetStateAction<BatchRow[]>>;
  running: boolean;
  timestamp: string;
  onStart: (entities: BatchPreviewResponse["entities"]) => void;
  onRetry: (indexes: number[]) => void;
  onCancel: () => void;
  onClear: () => void;
}

export function BatchWorkspace({ preview, rows, setRows, running, timestamp, onStart, onRetry, onCancel, onClear }: Props) {
  const [pending, setPending] = useState(preview.entities);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [risk, setRisk] = useState("all");
  const [type, setType] = useState("all");
  const [special, setSpecial] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [notice, setNotice] = useState<string | null>(null);

  const filtered = useMemo(() => rows.map((row, index) => ({ row, index })).filter(({ row }) => {
    const summary = row.investigation?.investigation_summary;
    if (risk !== "all" && (!summary || riskLabel(summary.posture).toLowerCase() !== risk)) return false;
    if (type !== "all" && row.entity.type !== type) return false;
    if (special === "failed" && row.state !== "failed") return false;
    if (special === "eligible" && (!row.investigation || !detectionEligible(row.investigation))) return false;
    return true;
  }), [rows, risk, type, special]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize);
  const completed = rows.filter((row) => row.state === "completed").length;
  const failed = rows.filter((row) => row.state === "failed").length;
  const queued = rows.filter((row) => row.state === "queued").length;
  const active = rows.filter((row) => row.state === "running").length;
  const selected = rows.map((row, index) => ({ row, index })).filter(({ row }) => row.selected && row.state === "completed" && row.investigation);

  function updateSelection(indexes: number[], selectedValue: boolean) {
    setRows((current) => current.map((row, index) => indexes.includes(index) && row.state === "completed" ? { ...row, selected: selectedValue } : row));
  }

  async function saveSelected() {
    let added = 0; let existing = 0; let failures = 0;
    for (const { row, index } of selected) {
      if (!row.investigation) continue;
      if (row.savedId) { existing += 1; continue; }
      try {
        const record = await saveInvestigation({
          title: `${entityLabel(row.entity.type)}: ${row.entity.value}`,
          investigation_type: row.entity.type,
          investigation_summary: row.investigation.investigation_summary,
        });
        setRows((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, savedId: record.id } : item));
        added += 1;
      } catch { failures += 1; }
    }
    setNotice(`${added} added, ${existing} already saved, ${failures} failed.`);
  }

  function exportJson() {
    downloadText("threatlens-batch.json", JSON.stringify({ format: "threatlens-batch", version: 1, exported_at: new Date().toISOString(), items: selected.map(({ row }) => ({ entity: row.entity, status: row.state, error_code: row.errorCode, investigation: row.investigation })) }, null, 2), "application/json");
  }

  function exportCsv() {
    downloadText("threatlens-batch.csv", rowsToCsv(selected.map(({ row }) => {
      const investigation = row.investigation!;
      const summary = investigation.investigation_summary;
      const providers = providerCounts(investigation);
      return { value: row.entity.normalized_value, type: row.entity.type, state: row.state, posture: summary.posture, confidence: summary.overall_confidence.score, findings: summary.findings.length, successfulProviders: providers.successful, failedProviders: providers.failed, conflict: investigation.threat_intelligence.agreement?.conflicted ?? false, errorCode: row.errorCode };
    })), "text/csv;charset=utf-8");
  }

  if (preview.requires_confirmation && rows.length === 0) {
    return <section className="w-full max-w-5xl mt-10 rounded-2xl border border-amber-500/30 bg-zinc-900 p-6 space-y-5" aria-label="Batch confirmation">
      <div><h2 className="text-lg font-semibold text-white">Confirm batch investigation</h2><p className="mt-1 text-sm text-zinc-400">{preview.supported} indicators found · {preview.duplicates} duplicates removed · {preview.invalid} invalid candidates · about {preview.estimated_ti_requests} TI requests</p></div>
      <p className="text-sm text-amber-300">{preview.quota_warning} Exposure providers and provider-specific limits may change actual usage.</p>
      <div className="grid gap-2 sm:grid-cols-2">{pending.map((entity) => <label key={`${entity.type}-${entity.normalized_value}`} className="flex items-center gap-3 rounded-lg border border-zinc-800 p-3 text-sm text-zinc-200"><input type="checkbox" checked onChange={() => setPending((current) => current.filter((item) => item !== entity))} /><span className="truncate font-mono">{entity.normalized_value}</span><span className="ml-auto text-xs text-zinc-500">{entity.type}</span></label>)}</div>
      <div className="flex gap-3"><button type="button" disabled={!pending.length} onClick={() => onStart(pending)} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">Run {pending.length} selected</button><button type="button" onClick={onClear} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300">Cancel</button></div>
    </section>;
  }

  return <section className="w-full max-w-5xl mt-10 space-y-4" aria-label="Batch IOC results">
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-4"><div className="flex flex-wrap items-center gap-3"><h2 className="text-lg font-semibold text-white">Batch results</h2><span className="text-sm text-zinc-400" role="status" aria-live="polite">{completed} of {rows.length} completed · {active} running · {failed} failed · {queued} queued</span><div className="ml-auto flex gap-2">{running && <button onClick={onCancel} className="rounded-lg border border-red-500/40 px-3 py-1.5 text-xs text-red-300">Cancel remaining</button>}{failed > 0 && <button disabled={running} onClick={() => onRetry(rows.flatMap((row, index) => row.state === "failed" && row.retryable ? [index] : []))} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200 disabled:opacity-40">Retry failed</button>}<button onClick={onClear} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400">Clear</button></div></div><p className="mt-2 text-xs text-zinc-500">{preview.supported} found · {preview.duplicates} duplicates removed · {preview.invalid} invalid candidates · about {preview.estimated_ti_requests} TI requests (estimate)</p><div className="mt-3 h-1.5 overflow-hidden rounded bg-zinc-800"><div className="h-full bg-emerald-500 transition-all" style={{ width: `${rows.length ? ((completed + failed) / rows.length) * 100 : 0}%` }} /></div></div>
    <div className="flex flex-wrap gap-2"><select aria-label="Filter by risk" value={risk} onChange={(event) => { setRisk(event.target.value); setPage(1); }} className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm"><option value="all">All risks</option>{["unknown", "low", "medium", "high", "critical"].map((value) => <option key={value}>{value}</option>)}</select><select aria-label="Filter by IOC type" value={type} onChange={(event) => { setType(event.target.value); setPage(1); }} className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm"><option value="all">All IOC types</option>{Array.from(new Set(rows.map((row) => row.entity.type))).map((value) => <option key={value} value={value}>{value}</option>)}</select><select aria-label="Filter batch state" value={special} onChange={(event) => { setSpecial(event.target.value); setPage(1); }} className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm"><option value="all">All results</option><option value="failed">Failed rows</option><option value="eligible">Detection eligible</option></select><select aria-label="Rows per page" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1); }} className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm"><option value="5">5 rows</option><option value="10">10 rows</option><option value="20">20 rows</option></select><button onClick={() => setExpanded(new Set(filtered.map(({ index }) => index)))} className="rounded-lg border border-zinc-800 px-3 py-2 text-xs">Expand all</button><button onClick={() => setExpanded(new Set())} className="rounded-lg border border-zinc-800 px-3 py-2 text-xs">Collapse all</button></div>
    {selected.length > 0 && <div className="sticky top-16 z-10 flex flex-wrap items-center gap-2 rounded-xl border border-sky-500/30 bg-zinc-950/95 p-3 shadow-xl"><span className="mr-auto text-sm text-sky-200">{selected.length} selected</span><button onClick={saveSelected} className="rounded-lg bg-sky-600 px-3 py-2 text-xs text-white">Save selected</button><button onClick={exportJson} className="rounded-lg border border-zinc-700 px-3 py-2 text-xs">Export JSON</button><button onClick={exportCsv} className="rounded-lg border border-zinc-700 px-3 py-2 text-xs">Export CSV</button></div>}
    {notice && <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200"><p>{notice}</p><div className="mt-1 flex flex-wrap gap-3">{rows.flatMap((row) => row.savedId ? [<Link key={row.savedId} href={`/workspace/${row.savedId}`} className="underline">View {row.entity.normalized_value}</Link>] : [])}</div></div>}
    <div className="flex gap-2 text-xs"><button onClick={() => updateSelection(pageItems.map(({ index }) => index), true)} className="underline text-zinc-300">Select current page</button><button onClick={() => updateSelection(rows.map((_, index) => index), true)} className="underline text-zinc-300">Select all completed</button><button onClick={() => updateSelection(rows.map((_, index) => index), false)} className="underline text-zinc-500">Clear selection</button></div>
    <div className="space-y-2">{pageItems.map(({ row, index }) => { const investigation = row.investigation; const summary = investigation?.investigation_summary; const counts = investigation ? providerCounts(investigation) : null; const isExpanded = expanded.has(index); return <article key={`${row.entity.type}-${row.entity.normalized_value}`} className="rounded-xl border border-zinc-800 bg-zinc-900/70 [content-visibility:auto]"><div className="flex flex-wrap items-center gap-3 p-4"><input aria-label={`Select ${row.entity.normalized_value}`} type="checkbox" checked={row.selected} disabled={row.state !== "completed"} onChange={(event) => updateSelection([index], event.target.checked)} /><span className={`h-2.5 w-2.5 rounded-full ${row.state === "completed" ? "bg-emerald-400" : row.state === "failed" ? "bg-red-400" : row.state === "running" ? "bg-sky-400 animate-pulse" : "bg-zinc-600"}`} /><div className="min-w-48 flex-1"><p className="truncate font-mono text-sm text-zinc-100">{row.entity.normalized_value}</p><p className="text-xs uppercase text-zinc-500">{row.entity.type} · {row.state}</p></div>{summary && <div className="text-xs text-zinc-400">{riskLabel(summary.posture)} ({summary.posture}) · confidence {summary.overall_confidence.score} · {summary.findings.length} findings · {counts?.successful}/{counts?.failed} providers {investigation?.threat_intelligence.agreement?.conflicted && <span className="text-amber-300">· conflict</span>} · {detectionEligible(investigation!) ? "detection eligible" : "not eligible"}</div>}{row.error && <span className="text-xs text-red-300">{row.error}</span>}{row.retryable && !running && <button onClick={() => onRetry([index])} className="rounded border border-zinc-700 px-2 py-1 text-xs">Retry</button>}{investigation && <button aria-expanded={isExpanded} aria-controls={`batch-detail-${index}`} onClick={() => setExpanded((current) => { const next = new Set(current); if (next.has(index)) next.delete(index); else next.add(index); return next; })} className="rounded px-2 py-1 text-zinc-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">{isExpanded ? "Collapse" : "Expand"}</button>}</div>{isExpanded && investigation && <div id={`batch-detail-${index}`} className="border-t border-zinc-800 px-4 pb-4"><InvestigationWorkspace data={investigation} timestamp={timestamp} /></div>}</article>; })}</div>
    <div className="flex items-center justify-center gap-3 text-sm"><button disabled={page <= 1} onClick={() => setPage((value) => value - 1)} className="disabled:opacity-30">Previous</button><span className="text-zinc-500">Page {page} of {pages}</span><button disabled={page >= pages} onClick={() => setPage((value) => value + 1)} className="disabled:opacity-30">Next</button></div>
  </section>;
}
