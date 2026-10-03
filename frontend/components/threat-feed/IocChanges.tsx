"use client";
import { useEffect, useState } from "react";
import { get } from "@/lib/api/client";
import { defang, downloadIocs } from "@/lib/iocReports";
import type { Ioc, IocReport } from "@/lib/api/iocReports";
import { feedControl } from "./FeedWorkflow";

type Revision = {
  id: string; observed_at: string; commit: string; parser_version: string;
  changed_fields: string[]; added: Ioc[]; removed: Ioc[];
  attribution?: string; license?: string; license_url?: string;
};
type Changes = { items: Revision[]; total: number; page: number; page_size: number; limited: boolean; baseline: string };

export function IocChanges({ report }: { report: IocReport }) {
  const [data, setData] = useState<Changes | null>(null);
  const [page, setPage] = useState(1);
  const [error, setError] = useState(false);
  const [open, setOpen] = useState<Set<string>>(new Set());
  useEffect(() => {
    const controller = new AbortController();
    setError(false);
    void get<Changes>(`/threat-feed/ioc-reports/${encodeURIComponent(report.id)}/changes?page=${page}`, controller.signal)
      .then((r) => { if (!controller.signal.aborted && Array.isArray(r.items)) setData(r); })
      .catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [page, report.id]);
  return <section className="space-y-3 rounded-xl border border-zinc-800 p-5">
    <h2>Observed IOC changes</h2>
    <p className="text-xs text-zinc-500">Current records started as the baseline. No historical vendor versions are invented.</p>
    {error && <p role="status">Change history unavailable.</p>}
    {data?.limited && <p className="text-xs text-amber-300">Limited history: older revisions were removed by retention or storage limits.</p>}
    {data?.items.map((r) => {
      const exportReport = { ...report, commit: r.commit, parser_version: r.parser_version,
        attribution: r.attribution ?? report.attribution, license: r.license ?? report.license,
        license_url: r.license_url ?? report.license_url };
      return <details key={r.id} onToggle={(e) => {
        const expanded = e.currentTarget.open;
        setOpen((old) => { const next = new Set(old); expanded ? next.add(r.id) : next.delete(r.id); return next; });
      }} className="rounded-lg bg-zinc-900 p-3">
        <summary className="cursor-pointer focus-visible:outline">{new Date(r.observed_at).toLocaleString()} · +{r.added.length} / −{r.removed.length}</summary>
        {open.has(r.id) && <>
          <p className="mt-2 text-xs text-zinc-500">Commit {r.commit.slice(0, 12)} · Parser {r.parser_version} · Fields: {r.changed_fields.join(", ") || "Indicators only"}</p>
          {([["Added", r.added], ["Removed", r.removed]] as const).map(([label, values]) => <div key={label}>
            <h3 className="mt-3 text-sm">{label}</h3>
            <ul className="max-h-48 overflow-auto text-xs">{values.map((i) => <li className="break-all font-mono" key={i.id}>{defang(i.value)}</li>)}</ul>
            <button className={feedControl} onClick={() => downloadIocs(exportReport, values, "json")}>Export {label.toLowerCase()} JSON</button>
          </div>)}
        </>}
      </details>;
    })}
    {data && !data.total && <p className="text-xs text-zinc-500">No retained changes observed after baseline.</p>}
    {data && <nav className="flex gap-3">
      <button className={feedControl} disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous changes</button>
      <span>Page {page}</span>
      <button className={feedControl} disabled={page * data.page_size >= data.total} onClick={() => setPage(page + 1)}>Next changes</button>
    </nav>}
  </section>;
}
