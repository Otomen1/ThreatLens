"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { getIocList, vendors, iocTypes, type IocReportList, type IocIndicatorList } from "@/lib/api/iocReports";
import { defang, readIocCache, writeIocCache } from "@/lib/iocReports";
import { refreshFeed } from "@/lib/api/threatFeed";
import { LoadingRows } from "@/components/ui/Skeleton";
import { useToast } from "@/components/ui/ToastProvider";

const control = "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40";
export function IocFeed() {
  const params = useSearchParams(); const router = useRouter(); const { notify } = useToast();
  const indicators = params.get("view") === "indicators";
  const filter = new URLSearchParams();
  for (const name of ["query", "vendor", "kind", "hours", "page"]) { const value = params.get(name); if (value) filter.set(name, value); }
  const key = `${indicators ? "indicators" : "reports"}?${filter}`;
  const [data, setData] = useState<IocReportList | IocIndicatorList | null>(null);
  const [status, setStatus] = useState(""); const [busy, setBusy] = useState(false);
  const sequence = useRef(0); const latest = useRef<typeof data>(null);
  const page = Math.max(1, Number(params.get("page")) || 1);
  const update = (name: string, value: string) => { const next = new URLSearchParams(params.toString()); next.set("tab", "iocs"); value ? next.set(name, value) : next.delete(name); if (name !== "page") next.delete("page"); router.replace(`/threat-feed?${next}`, { scroll: false }); };
  const load = useCallback(async (fresh = false, signal?: AbortSignal) => {
    const id = ++sequence.current;
    const cached = fresh ? null : readIocCache(key);
    if (cached) { setData(cached); latest.current = cached; }
    setStatus(latest.current ? "Updating IOC reports…" : "Loading IOC reports…");
    const [view, query] = key.split("?");
    try {
      const response = await getIocList(new URLSearchParams(query), view === "indicators", fresh, signal);
      if (id !== sequence.current || signal?.aborted) return;
      latest.current = response; setData(response); writeIocCache(key, response); setStatus("");
    } catch { if (!signal?.aborted && id === sequence.current) setStatus(latest.current ? "Could not update. Showing previously loaded data; filters may reflect the previous view." : "IOC reports are unavailable. Use Retry to try again."); }
  }, [key]);
  useEffect(() => { const controller = new AbortController(); void load(false, controller.signal); return () => controller.abort(); }, [load]);
  async function refresh() { setBusy(true); try { const outcome = await refreshFeed(); await load(true); const message = outcome.status === "cooldown" ? `Refresh cooling down${outcome.next_refresh_at ? ` until ${new Date(outcome.next_refresh_at).toLocaleTimeString()}` : ""}.` : "Feed refresh finished. Check source coverage below."; setStatus(message); notify(message); } catch { notify("Refresh unavailable; existing records retained.", "error"); } finally { setBusy(false); } }
  const reportData = data && "sources" in data ? data : null;
  const indicatorData = data && !("sources" in data) ? data : null;
  return <main className="mx-auto min-h-screen max-w-6xl space-y-5 px-4 py-8">
    <h2 className="text-xl font-semibold">IOC Reports</h2>
    <p className="text-sm text-zinc-400">Vendor-published indicators · Source-reported, not independently verified · Current activity unknown. “New” means newly collected or updated, not newly discovered malware.</p>
    <div className="flex flex-wrap gap-2"><button className={control} aria-pressed={!indicators} onClick={() => update("view", "")}>Reports</button><button className={control} aria-pressed={indicators} onClick={() => update("view", "indicators")}>Indicators</button></div>
    <div className="flex flex-wrap gap-3"><input aria-label="Search IOC reports" className={`${control} min-w-0 w-full basis-full sm:basis-auto sm:flex-1`} defaultValue={params.get("query") ?? ""} key={params.get("query") ?? ""} placeholder="Report title or exact IOC…" onKeyDown={(e) => { if (e.key === "Enter") update("query", e.currentTarget.value); }} onBlur={(e) => { if (e.currentTarget.value !== (params.get("query") ?? "")) update("query", e.currentTarget.value); }} /><select aria-label="IOC vendor" className={control} value={params.get("vendor") ?? ""} onChange={(e) => update("vendor", e.target.value)}><option value="">All vendors</option>{Object.entries(vendors).map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select><select aria-label="IOC type" className={control} value={params.get("kind") ?? ""} onChange={(e) => update("kind", e.target.value)}><option value="">All IOC types</option>{iocTypes.map((type) => <option key={type}>{type}</option>)}</select><select aria-label="IOC time range" className={control} value={params.get("hours") ?? "168"} onChange={(e) => update("hours", e.target.value)}><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select><button className={control} disabled={busy} onClick={() => void refresh()}>{busy ? "Refreshing…" : "Refresh IOC reports"}</button><button className={control} onClick={() => void load(true)}>Retry</button></div>
    <p role="status" aria-live="polite" className="text-xs text-zinc-500">{status || (reportData ? `Updated ${new Date(reportData.generated_at).toLocaleString()}` : "Loaded indicators")}</p>
    {reportData && <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{[["Reports", reportData.total], ["Unique IOCs", reportData.unique_indicators], ["Updated within 24h", reportData.recent_indicators], ["Vendors enabled", reportData.sources.filter((s) => s.enabled).length]].map(([label, value]) => <div key={label} className="rounded-xl border border-zinc-800 p-4"><p className="text-xs text-zinc-500">{label}</p><p className="mt-2 text-lg">{value}</p></div>)}</div>}
    {!data ? <LoadingRows rows={5} label="Loading IOC report table" /> : !data.items.length ? <div className="rounded-xl border border-zinc-800 p-6 text-sm text-zinc-400">No collected reports match these filters. Collection is bounded; source status below explains missing or pending coverage.</div> : <div role="table" aria-label="IOC reports" className="space-y-2">
      <div role="row" className="hidden grid-cols-[2fr_1fr_1fr_1fr] gap-3 px-4 text-xs text-zinc-500 md:grid">{(indicatorData ? ["Indicator", "Type", "Vendors", "Supporting reports"] : ["Report / source file", "Vendor", "Published / updated", "IOC count"]).map((label) => <span role="columnheader" key={label}>{label}</span>)}</div>
      {reportData ? reportData.items.map((item) => <div role="row" key={item.id} className="grid gap-3 rounded-xl border border-zinc-800 p-4 md:grid-cols-[2fr_1fr_1fr_1fr]"><div role="cell"><Link className="break-words text-sm text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={`/threat-feed/ioc-reports/${item.id}`}>{item.title}</Link><p className="mt-1 break-all text-xs text-zinc-500">{item.path}</p></div><div role="cell" className="text-xs text-zinc-400">{vendors[item.vendor as keyof typeof vendors] ?? item.vendor}</div><div role="cell" className="text-xs text-zinc-500"><p>Published: {item.published_at ? new Date(item.published_at).toLocaleDateString() : "Not supplied"}</p><p>Updated: {new Date(item.activity_at).toLocaleDateString()}</p></div><div role="cell" className="text-xs text-zinc-400">{item.indicator_count} IOCs{item.withdrawn ? " · Withdrawn" : ""}{item.warnings.length ? " · Coverage warning" : ""}</div></div>) : indicatorData?.items.map((item) => <div role="row" key={item.id} className="grid gap-3 rounded-xl border border-zinc-800 p-4 md:grid-cols-[2fr_1fr_1fr_1fr]"><div role="cell" className="break-all font-mono text-xs">{defang(item.value)}</div><div role="cell" className="text-xs">{item.type}</div><div role="cell" className="text-xs">{item.vendors.map((v) => vendors[v as keyof typeof vendors] ?? v).join(", ")}</div><div role="cell" className="space-y-2 text-xs">{item.reports.map((r) => <Link key={r.id} className="block text-sky-300 focus-visible:outline focus-visible:outline-sky-400" href={`/threat-feed/ioc-reports/${r.id}`}>{r.title}</Link>)}</div></div>)}
    </div>}
    {data && <nav aria-label="IOC pagination" className="flex items-center gap-4"><button className={control} disabled={page <= 1} onClick={() => update("page", String(page - 1))}>Previous</button><span className="text-sm text-zinc-400">Page {page} · {data.total} results</span><button className={control} disabled={page * data.page_size >= data.total} onClick={() => update("page", String(page + 1))}>Next</button></nav>}
    {reportData && <details className="rounded-xl border border-zinc-800 p-4" open><summary className="cursor-pointer text-sm focus-visible:outline focus-visible:outline-sky-400">Source coverage and synchronization</summary><div className="mt-3 grid gap-3 sm:grid-cols-2">{reportData.sources.map((s) => <section key={s.vendor} className="rounded-lg bg-zinc-900 p-3 text-xs text-zinc-400"><a href={s.url} target="_blank" rel="noreferrer" className="text-sky-300">{s.name} ↗</a><p>{s.status.replaceAll("_", " ")} · {s.pending} pending · {s.skipped} skipped files</p><p>Last success: {s.last_success_at ? new Date(s.last_success_at).toLocaleString() : "Not supplied"}</p>{s.safe_error && <p className="text-amber-300">{s.safe_error}</p>}{s.next_attempt_at && <p>Retry after {new Date(s.next_attempt_at).toLocaleString()}</p>}</section>)}</div></details>}
  </main>;
}
