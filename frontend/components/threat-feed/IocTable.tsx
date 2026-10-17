"use client";
import Link from "next/link";
import type { CSSProperties } from "react";
import { vendors, type IocReportList, type IocIndicatorList } from "@/lib/api/iocReports";
import { defang } from "@/lib/iocReports";
import { FEED_COLUMNS } from "@/lib/feedDisplay";
import { FeedDate, ReadDot, useFeedDisplay } from "./FeedExperience";
import { PreviewButton } from "./FeedPreview";
import { TargetingBadge } from "./FeedFilters";
import { FeedRowCheckbox, type FeedRowSelection } from "./FeedBulkActions";

export function IocTable({ reports, indicators, rowSelection }: { reports: IocReportList | null; indicators: IocIndicatorList | null; rowSelection?: FeedRowSelection }) {
  const { display, reading } = useFeedDisplay();
  const table = reports ? "ioc" : "indicators";
  const show = (key: string) => !display.hidden[table]?.includes(key);
  const columns = Object.entries(FEED_COLUMNS[table]).filter(([key]) => show(key));
  const style = { "--feed-grid": `minmax(0,2fr) ${columns.map(() => "minmax(0,1fr)").join(" ")}` } as CSSProperties;
  const row = `feed-news-row grid gap-3 rounded-xl border border-zinc-800 px-4 ${display.density === "comfortable" ? "py-6" : "py-4"} text-xs`;
  return <div role="table" aria-label="IOC reports" className="space-y-2" style={style}>
    <div role="row" className="feed-news-row hidden gap-3 px-4 text-xs text-zinc-500 md:grid"><span role="columnheader">{reports ? "Report / source file" : "Indicator"}</span>{columns.map(([key, label]) => <span role="columnheader" key={key}>{label}</span>)}</div>
    {reports ? reports.items.map((item) => <div role="row" key={item.id} className={row}>
      <div role="cell">{rowSelection && <FeedRowCheckbox {...rowSelection} id={item.id} title={item.title} />}<ReadDot kind="ioc" id={item.id} /><Link className={`break-words text-sm ${reading.has(`ioc:${item.id}`) ? "text-zinc-400" : "text-sky-300"} hover:underline`} href={`/threat-feed/ioc-reports/${item.id}`}>{item.title}</Link><TargetingBadge evidence={item.targeting_evidence} /><p className="mt-1 break-all text-zinc-500">{item.path}</p><PreviewButton kind="ioc" id={item.id} title={item.title} /></div>
      {show("vendor") && <div role="cell" className="text-zinc-400">{vendors[item.vendor as keyof typeof vendors] ?? item.vendor}</div>}
      {show("dates") && <div role="cell" className="text-zinc-500"><p>Published: <FeedDate value={item.published_at} /></p><p>Updated: <FeedDate value={item.activity_at} /></p></div>}
      {show("count") && <div role="cell" className="text-zinc-400">{item.indicator_count} IOCs{item.withdrawn ? " · Withdrawn" : ""}{item.warnings.length ? " · Coverage warning" : ""}</div>}
    </div>) : indicators?.items.map((item) => <div role="row" key={item.id} className={row}>
      <div role="cell" className="break-all font-mono">{defang(item.value)}</div>
      {show("type") && <div role="cell">{item.type}</div>}
      {show("vendor") && <div role="cell">{item.vendors.map((v) => vendors[v as keyof typeof vendors] ?? v).join(", ")}</div>}
      {show("reports") && <div role="cell" className="space-y-2">{item.reports.map((report) => <div key={report.id}><Link className="block text-sky-300" href={`/threat-feed/ioc-reports/${report.id}`}>{report.title}</Link><PreviewButton kind="ioc" id={report.id} title={report.title} /></div>)}</div>}
    </div>)}
  </div>;
}
