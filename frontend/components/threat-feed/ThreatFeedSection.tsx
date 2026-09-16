"use client";

import Link from "next/link";
import { useEffect } from "react";
import type { FeedItem, FeedRegion } from "@/lib/api/threatFeed";
import { markRegionSeen } from "@/lib/threatFeedState";

const labels: Record<FeedRegion, string> = { global: "Global", malaysia: "Malaysia", southeast_asia: "Southeast Asia" };
export function ThreatFeedSection({ region, items, total }: { region: FeedRegion; items: FeedItem[]; total: number }) {
  useEffect(() => { markRegionSeen(region); }, [region]);
  return <section className="rounded-2xl border border-zinc-800 bg-zinc-900/70">
    <header className="flex items-center justify-between border-b border-zinc-800 px-5 py-4"><div><h2 className="font-semibold text-white">{labels[region]}</h2><p className="text-xs text-zinc-500">{total} items · {items.length} newest shown</p></div><Link className="text-xs text-sky-400 hover:text-sky-300" href={`/threat-feed?region=${region}`}>View all</Link></header>
    {items.length === 0 ? <p className="p-8 text-center text-sm text-zinc-500">No matching reports yet.</p> : <ol className="divide-y divide-zinc-800">{items.map((item, index) => <li key={item.id} className="flex gap-4 px-5 py-4 content-auto"><span className="mt-0.5 text-xs tabular-nums text-zinc-600">{String(index + 1).padStart(2, "0")}</span><div className="min-w-0 flex-1"><Link className="font-medium text-zinc-100 hover:text-sky-300" href={`/threat-feed/${item.id}`}>{item.title}</Link><div className="mt-2 flex flex-wrap gap-2 text-[11px] text-zinc-500"><span>{item.source_name}</span><span>·</span><time>{new Date(item.published_at).toLocaleDateString()}</time><span className="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-400">{item.topic.replaceAll("_", " ")}</span>{item.severity && <span className="rounded border border-amber-700/60 px-1.5 py-0.5 text-amber-300">{item.severity}</span>}<span className="rounded border border-sky-800/60 px-1.5 py-0.5 text-sky-300">{item.relevance}</span></div></div></li>)}</ol>}
  </section>;
}
