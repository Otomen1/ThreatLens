"use client";

import Link from "next/link";
import { TargetingBadge } from "@/components/threat-feed/FeedFilters";
import { BookmarkButton } from "@/components/threat-feed/SavedFeed";
import { AddToCase } from "@/components/threat-feed/AddToCase";
import { RelatedIntelligence } from "@/components/threat-feed/FeedWorkflow";
import { FeedBadge, FeedSeverityBadge } from "@/components/threat-feed/FeedBadge";
import { FeedDate } from "@/components/threat-feed/FeedExperience";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { getVulnerability, type Vulnerability } from "@/lib/api/threatFeed";
import { markVulnerabilityViewed } from "@/lib/vulnerabilityFeedCache";
import { markFeedRead } from "@/lib/feedDisplay";
import { LoadingRows } from "@/components/ui/Skeleton";

export default function VulnerabilityDetail() {
  const { id } = useParams<{ id: string }>();
  const [item, setItem] = useState<Vulnerability | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void getVulnerability(id).then((record) => {
      if (active) { setItem(record); markVulnerabilityViewed(record.id); markFeedRead("vulnerability", record.id); }
    }).catch(() => { if (active) setError("This vulnerability record is unavailable."); });
    return () => { active = false; };
  }, [id]);
  return <main className="feed-detail min-h-screen">
    <Link href="/threat-feed?tab=vulnerabilities" className="inline-block text-sm text-sky-300 hover:underline">← Back to Vulnerabilities</Link>
    {error ? <p role="alert" className="feed-notice feed-notice-warning mt-6">{error}</p> : !item ? <LoadingRows rows={4} label="Loading vulnerability" /> : <>
      <header className="feed-detail-header mt-6">
        <p className="mb-3 font-mono text-sm text-sky-300">{item.cve_id ?? "CVE not assigned"}</p><h1>{item.title}</h1>
        <p className="mt-3 text-sm text-zinc-400">{item.sources.join(", ")} · CVE published: <FeedDate value={item.published_at} />{item.kev_added_at && ` · KEV added: ${new Date(item.kev_added_at).toLocaleDateString()}`}</p>
        <div className="mt-4 flex flex-wrap gap-2"><FeedSeverityBadge severity={item.severity} />{item.reported_zero_day && <FeedBadge tone="high">Reported zero-day</FeedBadge>}{item.known_exploited && <FeedBadge tone="critical">Known exploited</FeedBadge>}</div>
        <div className="feed-detail-actions">{item.cve_id && <><Link href={`/?q=${encodeURIComponent(item.cve_id)}`} className="feed-control feed-control-primary">Investigate CVE</Link><Link href={`/threat-feed?tab=poc&cve=${encodeURIComponent(item.cve_id)}`} className="feed-control">Find PoC & Tools</Link></>}<BookmarkButton kind="vulnerability" id={id} title={item.title} /></div>
      </header>
      <div className="feed-detail-grid">
        <div className="feed-detail-body">
          <section className="feed-detail-panel"><h2>Description</h2><p className="mt-4 text-sm leading-7 text-zinc-300">{item.description || "No description supplied."}</p></section>
          <section className="feed-detail-panel"><h2>Related reports and supporting sources</h2><p className="mt-2 text-xs leading-5 text-zinc-400">Zero-day labels require explicit source wording. Known exploitation alone does not establish zero-day status.</p><div className="mt-4 divide-y divide-zinc-800">{item.reports.map((report) => <div key={report.id} className="py-4"><a href={report.url} target="_blank" rel="noreferrer" className="text-sm text-sky-300 hover:underline">{report.title} ↗</a><p className="mt-2 text-xs text-zinc-400">{report.source_name} · {new Date(report.published_at).toLocaleDateString()}{report.zero_day && " · Reports a zero-day"}</p><p className="mt-2 text-sm leading-6 text-zinc-300">{report.excerpt}</p></div>)}</div><ul className="mt-5 space-y-3">{item.references.map((url) => <li key={url}><a href={url} target="_blank" rel="noreferrer" className="break-all text-xs text-sky-300 hover:underline">{url} ↗</a></li>)}</ul>{!item.reports.length && !item.references.length && <p className="mt-4 text-sm text-zinc-400">No related reports or source links supplied.</p>}</section>
          <RelatedIntelligence kind="vulnerability" id={id} />
        </div>
        <aside className="feed-detail-facts" aria-label="Vulnerability facts">
          <section className="feed-detail-panel"><h2>Affected products</h2><p className="mt-3 text-sm leading-6 text-zinc-300">{item.products.join(", ") || "Not specified by the available sources."}</p></section>
          <section className="feed-detail-panel"><h2>Source scores</h2>{item.scores.length ? <ul className="mt-4 space-y-4 text-xs text-zinc-400">{item.scores.map((score, index) => <li key={`${score.source}-${score.version}-${index}`}><p className="text-lg tabular-nums text-zinc-100">{score.score}<span className="text-xs text-zinc-400"> / 10</span></p><p className="mt-1">CVSS {score.version} · {score.severity ?? "Not rated"} · {score.source}</p></li>)}</ul> : <p className="mt-3 text-sm text-zinc-400">Not rated — no score supplied.</p>}</section>
          <TargetingBadge evidence={item.targeting_evidence} />
          <AddToCase kind="vulnerability" id={item.id} />
        </aside>
      </div>
    </>}
  </main>;
}
