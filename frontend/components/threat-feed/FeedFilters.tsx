"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { feedControl } from "./FeedWorkflow";
import { FilterSummary } from "@/components/ui/FilterSummary";

export function FeedFilters({ poc = false }: { poc?: boolean }) {
  const params = useSearchParams(); const router = useRouter();
  const names = poc ? ["tool", "kind"] : params.get("tab") === "vulnerabilities" ? ["query", "hours", "source", "severity", "category", "sort"] : params.get("tab") === "iocs" ? ["query", "hours", "vendor", "kind", "sort"] : ["query", "topic", "hours", "region", "sort"];
  const change = (key: string, value: string) => { const next = new URLSearchParams(params.toString()); value ? next.set(key, value) : next.delete(key); next.delete("page"); router.replace(`/threat-feed?${next}`, { scroll: false }); };
  const defaults: Record<string, string> = { hours: "168", sort: "newest", category: "all" };
  const filters = names.filter((name) => Boolean(params.get(name)) && params.get(name) !== defaults[name]);
  return <div className="mt-4 flex flex-wrap items-center gap-2">{!poc && <select aria-label="Feed activity sort" className={`${feedControl} bg-zinc-950`} value={params.get("sort") ?? "newest"} onChange={(e) => change("sort", e.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select>}<FilterSummary filters={filters.map((name) => ({ key: name, label: name, value: params.get(name)!, remove: () => change(name, "") }))} reset={() => { const next = new URLSearchParams(params.toString()); for (const name of names) next.delete(name); next.delete("page"); router.replace(`/threat-feed?${next}`, { scroll: false }); }} /></div>;
}
export type TargetEvidence = { region: string; source: string; field: string; excerpt: string; related_report: boolean };
export function TargetingBadge({ evidence }: { evidence?: TargetEvidence[] }) {
  if (!evidence?.length) return null;
  const first = [...evidence].sort((a, b) => Number(b.region === "malaysia") - Number(a.region === "malaysia"))[0];
  return <details className="mt-2 text-xs text-amber-200"><summary className="cursor-pointer focus-visible:outline">{first.related_report ? "Related report describes " : "Source reports "}{first.region === "malaysia" ? "Malaysia" : "Southeast Asia"} targeting</summary>{evidence.map((e, i) => <p key={i} className="mt-2 text-zinc-400">{e.source} · {e.field}: “{e.excerpt}”</p>)}<p className="mt-2 text-zinc-500">Regional targeting evidence is separate from section placement and does not establish current IOC activity.</p></details>;
}
