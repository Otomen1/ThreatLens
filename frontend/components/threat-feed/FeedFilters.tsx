"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { feedControl } from "./FeedWorkflow";

export function FeedFilters({ poc = false }: { poc?: boolean }) {
  const params = useSearchParams(); const router = useRouter();
  const names = poc ? ["tool", "kind"] : ["query", "topic", "hours", "region", "source", "severity", "category", "vendor", "kind", "sort"];
  const change = (key: string, value: string) => { const next = new URLSearchParams(params.toString()); value ? next.set(key, value) : next.delete(key); next.delete("page"); router.replace(`/threat-feed?${next}`, { scroll: false }); };
  const filters = names.filter((name) => params.has(name));
  return <div className="mt-4 flex flex-wrap items-center gap-2">{!poc && <select aria-label="Feed activity sort" className={`${feedControl} bg-zinc-950`} value={params.get("sort") ?? "newest"} onChange={(e) => change("sort", e.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select>}{filters.map((name) => <button key={name} aria-label={`Remove ${name} filter`} className={`${feedControl} max-w-full break-all text-xs`} onClick={() => change(name, "")}>{name}: {params.get(name)} ×</button>)}{filters.length > 0 && <button className={feedControl} onClick={() => { const next = new URLSearchParams(params.toString()); for (const name of names) next.delete(name); next.delete("page"); router.replace(`/threat-feed?${next}`, { scroll: false }); }}>Reset filters</button>}</div>;
}
export type TargetEvidence = { region: string; source: string; field: string; excerpt: string; related_report: boolean };
export function TargetingBadge({ evidence }: { evidence?: TargetEvidence[] }) {
  if (!evidence?.length) return null;
  const first = [...evidence].sort((a, b) => Number(b.region === "malaysia") - Number(a.region === "malaysia"))[0];
  return <details className="mt-2 text-xs text-amber-200"><summary className="cursor-pointer focus-visible:outline">{first.related_report ? "Related report describes " : "Source reports "}{first.region === "malaysia" ? "Malaysia" : "Southeast Asia"} targeting</summary>{evidence.map((e, i) => <p key={i} className="mt-2 text-zinc-400">{e.source} · {e.field}: “{e.excerpt}”</p>)}<p className="mt-2 text-zinc-500">Regional targeting evidence is separate from section placement and does not establish current IOC activity.</p></details>;
}
