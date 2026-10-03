"use client";

import Link from "next/link";
import { TargetingBadge } from "@/components/threat-feed/FeedFilters";
import { BookmarkButton } from "@/components/threat-feed/SavedFeed";
import { RelatedIntelligence } from "@/components/threat-feed/FeedWorkflow";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { getVulnerability, type Vulnerability } from "@/lib/api/threatFeed";
import { markVulnerabilityViewed } from "@/lib/vulnerabilityFeedCache";
import { LoadingRows } from "@/components/ui/Skeleton";

export default function VulnerabilityDetail() {
  const { id } = useParams<{ id: string }>();
  const [item, setItem] = useState<Vulnerability | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void getVulnerability(id).then((record) => {
      if (active) { setItem(record); markVulnerabilityViewed(record.id); }
    }).catch(() => { if (active) setError("This vulnerability record is unavailable."); });
    return () => { active = false; };
  }, [id]);
  return <main className="mx-auto min-h-screen max-w-4xl space-y-6 px-4 py-10">
    <Link href="/threat-feed?tab=vulnerabilities" className="text-sm text-sky-400 hover:underline">← Back to Vulnerabilities</Link>
    {error ? <p role="alert" className="text-red-300">{error}</p> : !item ? <LoadingRows rows={4} label="Loading vulnerability" /> : <>
      <header className="rounded-2xl border border-zinc-800 bg-zinc-900 p-6">
        <p className="font-mono text-sm text-sky-300">{item.cve_id ?? "CVE not assigned"}</p><h1 className="mt-3 text-2xl font-semibold">{item.title}</h1>
        <div className="mt-4 flex flex-wrap gap-3 text-xs text-zinc-400"><span>{item.severity ?? "Not rated"}</span>{item.reported_zero_day && <span className="text-amber-300">Reported zero-day</span>}{item.known_exploited && <span className="text-red-300">Known exploited</span>}</div>
        <p className="mt-3 text-xs text-zinc-500">CVE published: {item.published_at ? new Date(item.published_at).toLocaleString() : "Not specified"}{item.kev_added_at && ` · KEV added: ${new Date(item.kev_added_at).toLocaleDateString()}`}</p>
        {item.cve_id && <Link href={`/?q=${encodeURIComponent(item.cve_id)}`} className="mt-5 inline-block rounded-lg bg-sky-600 px-4 py-2 text-sm text-white hover:bg-sky-500">Investigate CVE</Link>}
        {item.cve_id && <Link href={`/threat-feed?tab=poc&cve=${encodeURIComponent(item.cve_id)}`} className="ml-3 mt-5 inline-block rounded-lg border border-zinc-700 px-4 py-2 text-sm text-sky-300 focus-visible:outline focus-visible:outline-sky-400">Find PoC & Tools</Link>}
        <BookmarkButton kind="vulnerability" id={id} title={item.title} />
      </header>
      <section className="rounded-2xl border border-zinc-800 p-6"><h2 className="font-medium">Description</h2><p className="mt-3 text-sm leading-6 text-zinc-300">{item.description || "No description supplied."}</p><h3 className="mt-5 text-sm font-medium">Affected products</h3><p className="mt-2 text-sm text-zinc-400">{item.products.join(", ") || "Not specified by the available sources."}</p></section>
      <section className="rounded-2xl border border-zinc-800 p-6"><h2 className="font-medium">Source scores</h2>{item.scores.length ? <ul className="mt-3 space-y-2 text-sm text-zinc-400">{item.scores.map((score, index) => <li key={`${score.source}-${score.version}-${index}`}>{score.score} / 10 · CVSS {score.version} · {score.severity ?? "Not rated"} · {score.source}</li>)}</ul> : <p className="mt-3 text-sm text-zinc-500">Not rated — no score supplied.</p>}</section>
      <section className="rounded-2xl border border-zinc-800 p-6"><h2 className="font-medium">Related reports and supporting sources</h2><p className="mt-2 text-xs text-zinc-500">Zero-day labels require explicit source wording. Known exploitation alone does not establish zero-day status.</p><div className="mt-4 space-y-4">{item.reports.map((report) => <div key={report.id}><a href={report.url} target="_blank" rel="noreferrer" className="text-sm text-sky-300 hover:underline">{report.title} ↗</a><p className="mt-1 text-xs text-zinc-500">{report.source_name} · {new Date(report.published_at).toLocaleDateString()}{report.zero_day && " · Reports a zero-day"}</p><p className="mt-2 text-sm text-zinc-400">{report.excerpt}</p></div>)}</div><ul className="mt-5 space-y-2">{item.references.map((url) => <li key={url}><a href={url} target="_blank" rel="noreferrer" className="break-all text-xs text-sky-400 hover:underline">{url} ↗</a></li>)}</ul></section>
      <TargetingBadge evidence={item.targeting_evidence} /><RelatedIntelligence kind="vulnerability" id={id} />
    </>}
  </main>;
}
