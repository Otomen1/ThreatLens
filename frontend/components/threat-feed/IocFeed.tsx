"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useFeedParams, useFeedReady } from "./FeedPanelContext";
import { getIocList, vendors, iocTypes, type IocReportList, type IocIndicatorList } from "@/lib/api/iocReports";
import { readIocCache, writeIocCache } from "@/lib/iocReports";
import { refreshFeed } from "@/lib/api/threatFeed";
import { LoadingRows } from "@/components/ui/Skeleton";
import { useToast } from "@/components/ui/ToastProvider";
import { FeedToolbar } from "./FeedToolbar";
import { IocTable } from "./IocTable";
import { useFeedSelection } from "@/hooks/useFeedSelection";
import { FeedBulkActions } from "./FeedBulkActions";
import { FeedStats, FeedNotice } from "./FeedUi";

const control = "feed-control";
export function IocFeed() {
  const params = useFeedParams(); const router = useRouter(); const { notify } = useToast();
  const indicators = params.get("view") === "indicators";
  const filter = new URLSearchParams();
  for (const name of ["query", "vendor", "kind", "hours", "page", "sort"]) { const value = params.get(name); if (value) filter.set(name, value); }
  const key = `${indicators ? "indicators" : "reports"}?${filter}`;
  const [data, setData] = useState<IocReportList | IocIndicatorList | null>(null);
  const [dataKey, setDataKey] = useState<string | null>(null);
  const [status, setStatus] = useState(""); const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  useFeedReady(Boolean(data) || !loading);
  const sequence = useRef(0); const latest = useRef<typeof data>(null);
  const page = Math.max(1, Number(params.get("page")) || 1);
  const update = (name: string, value: string) => { const next = new URLSearchParams(params.toString()); next.set("tab", "iocs"); value ? next.set(name, value) : next.delete(name); if (name !== "page") next.delete("page"); router.replace(`/threat-feed?${next}`, { scroll: false }); };
  const load = useCallback(async (fresh = false, signal?: AbortSignal) => {
    const id = ++sequence.current;
    setLoading(true);
    const cached = fresh ? null : readIocCache(key);
    if (cached) { setData(cached); latest.current = cached; setDataKey(key); }
    setStatus(latest.current ? "Updating IOC reports…" : "Loading IOC reports…");
    const [view, query] = key.split("?");
    try {
      const response = await getIocList(new URLSearchParams(query), view === "indicators", fresh, signal);
      if (id !== sequence.current || signal?.aborted) return;
      latest.current = response; setData(response); setDataKey(key); writeIocCache(key, response); setStatus("");
    } catch { if (!signal?.aborted && id === sequence.current) setStatus(latest.current ? "Could not update. Showing previously loaded data; filters may reflect the previous view." : "IOC reports are unavailable. Use Retry to try again."); }
    finally { if (!signal?.aborted && id === sequence.current) setLoading(false); }
  }, [key]);
  useEffect(() => { const controller = new AbortController(); void load(false, controller.signal); return () => controller.abort(); }, [load]);
  async function refresh() { setBusy(true); try { const outcome = await refreshFeed(); await load(true); const message = outcome.status === "cooldown" ? `Refresh cooling down${outcome.next_refresh_at ? ` until ${new Date(outcome.next_refresh_at).toLocaleTimeString()}` : ""}.` : "Feed refresh finished. Check source coverage below."; setStatus(message); notify(message); } catch { notify("Refresh unavailable; existing records retained.", "error"); } finally { setBusy(false); } }
  const reportData = data && "sources" in data ? data : null;
  const indicatorData = data && !("sources" in data) ? data : null;
  const selection = useFeedSelection(key, reportData?.items ?? []);
  const selectionPaused = loading || dataKey !== key;
  return <main data-list-ready={Boolean(data)} className="feed-page mx-auto min-h-screen max-w-6xl space-y-5 px-4">
    <h2 className="sr-only">IOC Reports</h2>
    {reportData && <FeedStats label="IOC report activity" columns={4} items={[["Reports", reportData.total], ["Unique IOCs", reportData.unique_indicators], ["Updated within 24h", reportData.recent_indicators], ["Vendors enabled", reportData.sources.filter((s) => s.enabled).length]].map(([label, value]) => ({ label: String(label), value }))} />}
    <FeedToolbar table={indicators ? "indicators" : "ioc"} actions={<><button className={`${control} feed-control-primary`} disabled={busy || loading} onClick={() => void load(true)}>Reload saved data</button><button className={control} disabled={busy} onClick={() => void refresh()}>{busy ? "Refreshing…" : "Refresh IOC reports"}</button></>}><div className="flex flex-wrap gap-2" aria-label="IOC view"><button className={`${control} ${!indicators ? "feed-control-primary" : ""}`} aria-pressed={!indicators} onClick={() => update("view", "")}>Reports</button><button className={`${control} ${indicators ? "feed-control-primary" : ""}`} aria-pressed={indicators} onClick={() => update("view", "indicators")}>Indicators</button></div>
    <div className="flex flex-wrap gap-3"><input aria-label="Search IOC reports" className={`${control} min-w-0 w-full basis-full sm:basis-auto sm:flex-1`} defaultValue={params.get("query") ?? ""} key={params.get("query") ?? ""} placeholder="Report title or exact IOC…" onKeyDown={(e) => { if (e.key === "Enter") update("query", e.currentTarget.value); }} onBlur={(e) => { if (e.currentTarget.value !== (params.get("query") ?? "")) update("query", e.currentTarget.value); }} /><select aria-label="IOC vendor" className={control} value={params.get("vendor") ?? ""} onChange={(e) => update("vendor", e.target.value)}><option value="">All vendors</option>{Object.entries(vendors).map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select><select aria-label="IOC type" className={control} value={params.get("kind") ?? ""} onChange={(e) => update("kind", e.target.value)}><option value="">All IOC types</option>{iocTypes.map((type) => <option key={type}>{type}</option>)}</select><select aria-label="IOC time range" className={control} value={params.get("hours") ?? "168"} onChange={(e) => update("hours", e.target.value)}><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select></div>
    </FeedToolbar>
    <p className="text-xs leading-5 text-zinc-400">Vendor-published · Source-reported and unverified · Current activity unknown. “New” means newly collected or updated.</p>
    <FeedNotice warning={/Could not|unavailable|cooling/.test(status)}>{status || (reportData ? `Updated ${new Date(reportData.generated_at).toLocaleString()}` : "Loaded indicators")}</FeedNotice>
    {(!loading && status.startsWith("Could not") || (!loading && !data)) && <button className={control} onClick={() => void load(true)}>Retry</button>}
    {!indicators && reportData && <FeedBulkActions key={key} kind="ioc" items={reportData.items} selection={selection} disabled={selectionPaused} />}
    {!data ? loading ? <LoadingRows search rows={5} label="Loading IOC reports…" /> : <p role="alert" className="rounded-xl border border-zinc-800 p-6 text-sm text-zinc-400">Reports could not be loaded. Use Retry above; no investigation providers will be called.</p> : !data.items.length ? <div className="rounded-xl border border-zinc-800 p-6 text-sm text-zinc-400">No collected reports match these filters. Collection is bounded; source status below explains missing or pending coverage.</div> : <IocTable reports={reportData} indicators={indicatorData} rowSelection={!indicators ? { selection, disabled: selectionPaused } : undefined} />}
    {data && <nav aria-label="IOC pagination" className="feed-pagination"><button className={control} disabled={page <= 1} onClick={() => update("page", String(page - 1))}>Previous</button><span>Page {page} · {data.total} results</span><button className={control} disabled={page * data.page_size >= data.total} onClick={() => update("page", String(page + 1))}>Next</button></nav>}
    {reportData && <details className="rounded-xl border border-zinc-800 p-4"><summary className="cursor-pointer text-sm focus-visible:outline focus-visible:outline-sky-400">Source coverage and synchronization</summary><div className="mt-3 grid gap-3 sm:grid-cols-2">{reportData.sources.map((s) => <section key={s.vendor} className="rounded-lg bg-zinc-900 p-3 text-xs text-zinc-400"><a href={s.url} target="_blank" rel="noreferrer" className="text-sky-300">{s.name} ↗</a><p>{s.status.replaceAll("_", " ")} · {s.pending} pending · {s.skipped} skipped files</p><p>Last success: {s.last_success_at ? new Date(s.last_success_at).toLocaleString() : "Not supplied"}</p>{s.safe_error && <p className="text-amber-300">{s.safe_error}</p>}{s.next_attempt_at && <p>Retry after {new Date(s.next_attempt_at).toLocaleString()}</p>}</section>)}</div></details>}
  </main>;
}
