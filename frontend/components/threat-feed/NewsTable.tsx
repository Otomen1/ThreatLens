"use client";

import Link from "next/link";
import { TargetingBadge } from "./FeedFilters";
import type { CSSProperties } from "react";
import type { FeedItem } from "@/lib/api/threatFeed";
import { NEWS_REGION_DETAILS } from "@/lib/newsFeed";
import { FeedDate, ReadDot, useFeedDisplay } from "./FeedExperience";
import { PreviewButton } from "./FeedPreview";
import { FeedRowCheckbox, type FeedRowSelection } from "./FeedBulkActions";

const severityStyles: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/10 text-red-300",
  high: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  medium: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-xs text-zinc-600">Not rated</span>;
  const normalized = severity.toLowerCase();
  return <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium capitalize ${severityStyles[normalized] ?? "border-zinc-700 bg-zinc-800 text-zinc-300"}`}>{normalized}</span>;
}

export function NewsTable({ title, items, total, offset = 0, rowSelection }: { title: string; items: FeedItem[]; total: number; offset?: number; rowSelection?: FeedRowSelection }) {
  const { display, reading } = useFeedDisplay();
  const show = (key: string) => !display.hidden.news?.includes(key);
  const grid = ["32px", "minmax(260px,1fr)", show("source") ? "140px" : "", show("age") ? "100px" : "", show("category") ? "130px" : "", show("severity") ? "90px" : "", "20px"].filter(Boolean).join(" ");
  const spacing = display.density === "comfortable" ? "py-5" : "py-3";
  return <section style={{ "--feed-grid": grid } as CSSProperties} className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60">
    <header className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900 px-4 py-3"><h2 className="text-sm font-semibold text-zinc-100">{title}</h2><span className="text-xs tabular-nums text-zinc-400">{total} matching</span></header>
    {items.length === 0 ? <p className="p-8 text-center text-sm text-zinc-500">No matching reports yet.</p> : <div className="overflow-x-auto"><div role="table" aria-label={title}>
      <div role="row" className="feed-news-row hidden gap-3 border-b border-zinc-800 px-4 py-2 text-[10px] text-zinc-500 md:grid"><span role="columnheader">#</span><span role="columnheader">Title</span>{show("source") && <span role="columnheader">Source</span>}{show("age") && <span role="columnheader">Age</span>}{show("category") && <span role="columnheader">Category</span>}{show("severity") && <span role="columnheader">Severity</span>}<span aria-hidden="true" /></div>
      <ol className="divide-y divide-zinc-800/80">{items.map((item, index) => <li key={item.id} role="row" className={`feed-news-row content-auto grid gap-3 px-4 ${spacing} text-xs transition-colors hover:bg-zinc-800/35 md:items-center`}>
        <span role="cell" className="hidden tabular-nums text-zinc-600 md:block">{offset + index + 1}</span>
        <div role="cell" className="min-w-0">{rowSelection && <FeedRowCheckbox {...rowSelection} id={item.id} title={item.title} />}<ReadDot kind="news" id={item.id} /><Link className={`font-medium leading-5 ${reading.has(`news:${item.id}`) ? "text-zinc-400" : "text-zinc-100"} hover:text-sky-300`} href={`/threat-feed/${item.id}`}>{item.title}</Link><TargetingBadge evidence={item.targeting_evidence} /><span className="ml-2 inline-flex rounded-full border border-sky-700/50 bg-sky-500/10 px-1.5 py-0.5 text-[9px] capitalize text-sky-300">{NEWS_REGION_DETAILS[item.region].label}</span><div><PreviewButton kind="news" id={item.id} title={item.title} /></div></div>
        {show("source") && <div role="cell" className="flex justify-between gap-3 text-zinc-400 md:block"><span className="text-zinc-600 md:hidden">Source</span><span className="truncate">{item.source_name}</span></div>}
        {show("age") && <div role="cell" className="flex justify-between gap-3 text-zinc-500 md:block"><span className="text-zinc-600 md:hidden">Age</span><FeedDate value={item.published_at} relative /></div>}
        {show("category") && <div role="cell" className="flex justify-between gap-3 md:block"><span className="text-zinc-600 md:hidden">Category</span><span className="inline-flex rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-[10px] capitalize text-zinc-300">{item.topic.replaceAll("_", " ")}</span></div>}
        {show("severity") && <div role="cell" className="flex justify-between gap-3 md:block"><span className="text-zinc-600 md:hidden">Severity</span><SeverityBadge severity={item.severity} /></div>}
        <Link aria-label={`Open ${item.title}`} href={`/threat-feed/${item.id}`} className="hidden text-right text-lg text-zinc-600 hover:text-sky-300 md:block">›</Link>
      </li>)}</ol>
    </div></div>}
  </section>;
}
