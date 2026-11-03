"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { TargetingBadge } from "@/components/threat-feed/FeedFilters";
import { BookmarkButton } from "@/components/threat-feed/SavedFeed";
import { AddToCase } from "@/components/threat-feed/AddToCase";
import { RelatedIntelligence } from "@/components/threat-feed/FeedWorkflow";
import { FeedBadge, FeedSeverityBadge } from "@/components/threat-feed/FeedBadge";
import { FeedDate } from "@/components/threat-feed/FeedExperience";
import { LoadingRows } from "@/components/ui/Skeleton";
import { getFeedItem, type FeedItem } from "@/lib/api/threatFeed";
import { markViewed } from "@/lib/threatFeedState";
import { NEWS_REGION_DETAILS } from "@/lib/newsFeed";

export default function ThreatFeedDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [item, setItem] = useState<FeedItem | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void getFeedItem(id).then((value) => { if (active) { setItem(value); markViewed(value.id); } }).catch(() => { if (active) setError("This feed item is unavailable."); });
    return () => { active = false; };
  }, [id]);
  return <main className="feed-detail min-h-screen">
    <Link href="/threat-feed" className="inline-block text-sm text-sky-300 hover:underline">← Back to Threat Feed</Link>
    {error ? <p role="alert" className="feed-notice feed-notice-warning mt-6">{error}</p> : !item ? <LoadingRows rows={4} label="Loading report…" /> : <>
      <header className="feed-detail-header mt-6">
        <div className="mb-3 flex flex-wrap gap-2"><FeedBadge>{item.topic.replaceAll("_", " ")}</FeedBadge><FeedSeverityBadge severity={item.severity ?? null} /></div>
        <h1>{item.title}</h1>
        <p className="mt-3 text-sm text-zinc-400">{item.source_name} · <FeedDate value={item.published_at} /></p>
        <div className="feed-detail-actions"><a href={item.url} target="_blank" rel="noreferrer" className="feed-control feed-control-primary">Read at publisher ↗</a><BookmarkButton kind="news" id={id} title={item.title} /></div>
      </header>
      <div className="feed-detail-grid">
        <div className="feed-detail-body">
          <section className="feed-detail-panel"><h2>Structured summary</h2><p className="mt-4 whitespace-pre-line text-sm leading-7 text-zinc-300">{item.summary}</p><p className="mt-4 text-xs leading-5 text-zinc-400">Generated deterministically from publisher-supplied metadata. Open the source for full context.</p></section>
          <section className="feed-detail-panel"><h2>Source-reported entities</h2><p className="mt-2 text-xs text-amber-200">Unverified — not automatically treated as malicious.</p>
            {item.entities.length === 0 ? <p className="mt-4 text-sm text-zinc-400">No supported entities were present in the source metadata.</p> : <div className="mt-4 divide-y divide-zinc-800">{item.entities.map((entity) => <div key={`${entity.type}-${entity.normalized_value}`} className="flex flex-wrap items-center justify-between gap-3 py-4"><div className="min-w-0"><p className="break-all font-mono text-sm text-zinc-200">{entity.value}</p><p className="mt-1 text-xs text-zinc-400">{entity.type} · source-reported · unverified</p></div><Link href={`/?q=${encodeURIComponent(entity.normalized_value)}`} className="feed-control">Investigate</Link></div>)}</div>}
          </section>
          <RelatedIntelligence kind="news" id={id} />
        </div>
        <aside className="feed-detail-facts" aria-label="Report facts">
          <section className="feed-detail-panel"><h2>Report details</h2><dl className="mt-4 space-y-4 text-xs"><div><dt className="text-zinc-400">Publisher</dt><dd className="mt-1 text-zinc-200">{item.source_name}</dd></div><div><dt className="text-zinc-400">Section</dt><dd className="mt-1 text-zinc-200">{NEWS_REGION_DETAILS[item.region].label}</dd></div><div><dt className="text-zinc-400">Published</dt><dd className="mt-1 text-zinc-200"><FeedDate value={item.published_at} /></dd></div></dl></section>
          <section className="feed-detail-panel"><h2>Why this appears in {item.region.replaceAll("_", " ")}</h2><ul className="mt-3 list-inside list-disc space-y-2 text-xs leading-5 text-zinc-400">{item.region_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul><p className="mt-3 text-xs leading-5 text-zinc-400">Section placement is separate from explicit regional targeting.</p><TargetingBadge evidence={item.targeting_evidence} /></section>
          <AddToCase kind="news" id={item.id} />
        </aside>
      </div>
    </>}
  </main>;
}
