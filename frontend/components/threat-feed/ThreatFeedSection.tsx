"use client";

import Link from "next/link";
import { useEffect } from "react";
import type { FeedItem, FeedRegion } from "@/lib/api/threatFeed";
import { markRegionSeen } from "@/lib/threatFeedState";

const regionDetails: Record<FeedRegion, { icon: string; label: string }> = {
  global: { icon: "◎", label: "Global" },
  malaysia: { icon: "🇲🇾", label: "Malaysia" },
  southeast_asia: { icon: "◫", label: "Southeast Asia" },
};

const severityStyles: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/10 text-red-300",
  high: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  medium: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};

function relativeAge(value: string): string {
  const minutes = Math.floor(Math.max(0, Date.now() - new Date(value).getTime()) / 60_000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-xs text-zinc-600">Not rated</span>;
  const normalized = severity.toLowerCase();
  return <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium capitalize ${severityStyles[normalized] ?? "border-zinc-700 bg-zinc-800 text-zinc-300"}`}>{normalized}</span>;
}

export function ThreatFeedSection({ region, items, total }: { region: FeedRegion; items: FeedItem[]; total: number }) {
  const details = regionDetails[region];
  useEffect(() => { markRegionSeen(region); }, [region]);
  return <section className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60">
    <header className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900 px-4 py-3"><div className="flex items-center gap-2"><span aria-hidden="true" className="text-sky-400">{details.icon}</span><h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-100">{details.label}</h2><span className="rounded-full bg-zinc-800 px-2 py-0.5 text-[10px] tabular-nums text-zinc-400">{total}</span></div><Link className="text-xs text-sky-400 hover:text-sky-300" href={`/threat-feed?region=${region}`}>View all <span aria-hidden="true">›</span></Link></header>
    {items.length === 0 ? <p className="p-8 text-center text-sm text-zinc-500">No matching reports yet.</p> : <div role="table" aria-label={`${details.label} threat reports`}>
      <div role="row" className="hidden grid-cols-[32px_minmax(260px,1fr)_140px_100px_130px_90px_20px] gap-3 border-b border-zinc-800 px-4 py-2 text-[10px] text-zinc-500 md:grid"><span role="columnheader">#</span><span role="columnheader">Title</span><span role="columnheader">Source</span><span role="columnheader">Age</span><span role="columnheader">Category</span><span role="columnheader">Severity</span><span aria-hidden="true" /></div>
      <ol className="divide-y divide-zinc-800/80">{items.map((item, index) => <li key={item.id} role="row" className="content-auto grid gap-3 px-4 py-3 text-xs transition-colors hover:bg-zinc-800/35 md:grid-cols-[32px_minmax(260px,1fr)_140px_100px_130px_90px_20px] md:items-center">
        <span role="cell" className="hidden tabular-nums text-zinc-600 md:block">{index + 1}</span>
        <div role="cell" className="min-w-0"><Link className="font-medium leading-5 text-zinc-100 hover:text-sky-300" href={`/threat-feed/${item.id}`}>{item.title}</Link>{region !== "global" && <span className="ml-2 inline-flex rounded-full border border-sky-700/50 bg-sky-500/10 px-1.5 py-0.5 text-[9px] capitalize text-sky-300">{item.relevance}</span>}</div>
        <div role="cell" className="flex justify-between gap-3 text-zinc-400 md:block"><span className="text-zinc-600 md:hidden">Source</span><span className="truncate">{item.source_name}</span></div>
        <div role="cell" className="flex justify-between gap-3 text-zinc-500 md:block"><span className="text-zinc-600 md:hidden">Age</span><time dateTime={item.published_at} suppressHydrationWarning>{relativeAge(item.published_at)}</time></div>
        <div role="cell" className="flex justify-between gap-3 md:block"><span className="text-zinc-600 md:hidden">Category</span><span className="inline-flex rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-[10px] capitalize text-zinc-300">{item.topic.replaceAll("_", " ")}</span></div>
        <div role="cell" className="flex justify-between gap-3 md:block"><span className="text-zinc-600 md:hidden">Severity</span><SeverityBadge severity={item.severity} /></div>
        <Link aria-label={`Open ${item.title}`} href={`/threat-feed/${item.id}`} className="hidden text-right text-lg text-zinc-600 hover:text-sky-300 md:block">›</Link>
      </li>)}</ol>
    </div>}
  </section>;
}
