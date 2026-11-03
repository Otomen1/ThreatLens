"use client";

import Link from "next/link";
import { TargetingBadge } from "./FeedFilters";
import type { CSSProperties } from "react";
import type { FeedItem } from "@/lib/api/threatFeed";
import { NEWS_REGION_DETAILS } from "@/lib/newsFeed";
import { FeedDate, ReadDot, useFeedDisplay } from "./FeedExperience";
import { PreviewButton } from "./FeedPreview";
import { FeedRowCheckbox, type FeedRowSelection } from "./FeedBulkActions";
import { FeedBadge, FeedSeverityBadge } from "./FeedBadge";

export function NewsTable({ title, items, total, offset = 0, rowSelection, showRegion = true }: { title: string; items: FeedItem[]; total: number; offset?: number; rowSelection?: FeedRowSelection; showRegion?: boolean }) {
  const { display, reading } = useFeedDisplay();
  const show = (key: string) => !display.hidden.news?.includes(key);
  const grid = ["24px", "minmax(220px,1fr)", show("source") ? "130px" : "", show("age") ? "80px" : "", show("category") ? "110px" : "", show("severity") ? "80px" : "", "36px"].filter(Boolean).join(" ");
  const spacing = display.density === "comfortable" ? "py-5" : "py-3";
  return <section style={{ "--feed-grid": grid } as CSSProperties} className="feed-news-list overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
    <header className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900 px-4 py-3"><h2 className="text-sm font-semibold text-zinc-100">{title}</h2><span className="text-xs tabular-nums text-zinc-400">{total} matching</span></header>
    {items.length === 0 ? <p className="p-8 text-center text-sm text-zinc-500">No matching reports yet.</p> : <div className="overflow-x-auto"><div role="table" aria-label={title}>
      <div role="row" className="feed-news-row hidden gap-3 border-b border-zinc-800 px-4 py-2 text-xs text-zinc-400 md:grid"><span role="columnheader">#</span><span role="columnheader">Title</span>{show("source") && <span role="columnheader">Source</span>}{show("age") && <span role="columnheader">Age</span>}{show("category") && <span role="columnheader">Category</span>}{show("severity") && <span role="columnheader">Severity</span>}<span aria-hidden="true" /></div>
      <ol className="divide-y divide-zinc-800/80">{items.map((item, index) => <li key={item.id} role="row" className={`feed-news-row content-auto grid gap-3 px-4 ${spacing} text-xs transition-colors hover:bg-zinc-800/35 md:items-center`}>
        <span role="cell" className="hidden tabular-nums text-zinc-400 md:block">{offset + index + 1}</span>
        <div role="cell" className="feed-news-title-cell min-w-0"><div className="flex items-start gap-1">{rowSelection && <FeedRowCheckbox {...rowSelection} id={item.id} title={item.title} />}<div className="min-w-0 flex-1"><div className="flex items-start gap-1"><ReadDot kind="news" id={item.id} /><Link title={item.title} className={`feed-title-clamp feed-interactive text-sm leading-6 ${reading.has(`news:${item.id}`) ? "font-normal text-zinc-300" : "font-semibold text-zinc-100"} hover:text-sky-300`} href={`/threat-feed/${item.id}`}>{item.title}</Link></div><TargetingBadge evidence={item.targeting_evidence} />{showRegion && <span className="mt-1 inline-flex"><FeedBadge>{NEWS_REGION_DETAILS[item.region].label}</FeedBadge></span>}</div></div></div>
        {show("source") && <div role="cell" className="flex justify-between gap-3 text-zinc-400 md:block"><span className="text-zinc-400 md:hidden">Source</span><span className="truncate">{item.source_name}</span></div>}
        {show("age") && <div role="cell" className="flex justify-between gap-3 text-zinc-400 md:block"><span className="text-zinc-400 md:hidden">Age</span><FeedDate value={item.published_at} relative /></div>}
        {show("category") && <div role="cell" className="flex justify-between gap-3 md:block"><span className="text-zinc-400 md:hidden">Category</span><FeedBadge>{item.topic.replaceAll("_", " ")}</FeedBadge></div>}
        {show("severity") && <div role="cell" className="flex justify-between gap-3 md:block"><span className="text-zinc-400 md:hidden">Severity</span><FeedSeverityBadge severity={item.severity} /></div>}
        <div role="cell" className="justify-self-end"><PreviewButton kind="news" id={item.id} title={item.title} /></div>
      </li>)}</ol>
    </div></div>}
  </section>;
}
