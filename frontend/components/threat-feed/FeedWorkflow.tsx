"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { get } from "@/lib/api/client";

export const feedControl = "rounded-lg border border-zinc-700 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-sky-400";
type Reference = { kind: "news" | "vulnerability" | "ioc"; id: string; title: string; href: string; source: string; activity_at: string };
type Search = { groups: Record<string, { items: Reference[]; total: number; page: number; page_size: number }>; poc_cve: string | null };
type Related = { items: { record: Reference; reason: string; supporting_values: string[] }[]; cves: string[] };

export function FeedSearchBox({ compact = false }: { compact?: boolean }) {
  const params = useSearchParams(); const router = useRouter();
  return <form className={`${compact ? "mt-2" : "mt-5"} flex gap-2`} onSubmit={(e) => {
    e.preventDefault(); const query = String(new FormData(e.currentTarget).get("q") ?? "").trim();
    if (query) router.push(`/threat-feed?view=search&q=${encodeURIComponent(query)}`);
  }}><input key={params.get("q") ?? ""} name="q" aria-label="Search all threat intelligence" maxLength={200} defaultValue={params.get("q") ?? ""} placeholder="Search a CVE, IOC, product, or report…" className={`${feedControl} min-w-0 flex-1 bg-zinc-950`} /><button aria-label="Search feed" className={feedControl}>Search</button><Link href="/threat-feed?view=saved" className={feedControl}>Saved</Link></form>;
}

export function UnifiedFeedSearch() {
  const params = useSearchParams(); const router = useRouter();
  const key = params.toString(); const [data, setData] = useState<Search | null>(null); const [message, setMessage] = useState("Loading stored results…");
  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams(key); query.delete("view"); query.delete("tab");
    setMessage("Updating stored results…");
    void get<Search>(`/threat-feed/search?${query}`, controller.signal).then((value) => {
      if (!controller.signal.aborted) { setData(value); setMessage(""); }
    }).catch(() => { if (!controller.signal.aborted) setMessage("Search unavailable. Previous results retained."); });
    return () => controller.abort();
  }, [key]);
  const update = (name: string, value: string) => { const next = new URLSearchParams(key); next.set(name, value); if (name === "sort") for (const k of ["news", "vulnerability", "ioc"]) next.delete(`${k}_page`); router.replace(`/threat-feed?${next}`, { scroll: false }); };
  return <main className="mx-auto max-w-6xl space-y-5 px-4 py-8"><h2 className="text-xl">Search results</h2><p role="status" className="text-sm text-zinc-400">{message}</p><select aria-label="Search sort" value={params.get("sort") ?? "newest"} onChange={(e) => update("sort", e.target.value)} className={`${feedControl} bg-zinc-950`}><option value="newest">Newest activity</option><option value="oldest">Oldest activity</option></select>{data?.poc_cve && <p><Link className="text-sky-300" href={`/threat-feed?tab=poc&cve=${encodeURIComponent(data.poc_cve)}`}>Find PoC & Tools for {data.poc_cve}</Link><span className="ml-2 text-xs text-zinc-500">Manual lookup; no request starts here.</span></p>}{data && Object.entries(data.groups).map(([kind, group]) => <section key={kind} className="space-y-3 rounded-xl border border-zinc-800 p-4"><h3 className="capitalize">{kind === "ioc" ? "IOC Reports / Indicators" : kind} · {group.total}</h3>{group.items.length ? group.items.map((r) => <div key={r.id} className="rounded-lg bg-zinc-900 p-3"><Link href={r.href} className="text-sm text-sky-300 focus-visible:outline">{r.title}</Link><p className="mt-1 text-xs text-zinc-500">{r.source} · {new Date(r.activity_at).toLocaleDateString()}</p></div>) : <p className="text-xs text-zinc-500">No stored matches.</p>}<nav aria-label={`${kind} search pagination`} className="flex items-center gap-3"><button disabled={group.page <= 1} className={feedControl} onClick={() => update(`${kind}_page`, String(group.page - 1))}>Previous</button><span>Page {group.page}</span><button disabled={group.page * 20 >= group.total} className={feedControl} onClick={() => update(`${kind}_page`, String(group.page + 1))}>Next</button></nav></section>)}</main>;
}

export function RelatedIntelligence({ kind, id }: { kind: Reference["kind"]; id: string }) {
  const [data, setData] = useState<Related | null>(null); const [error, setError] = useState(false);
  useEffect(() => { const controller = new AbortController(); setData(null); setError(false);
    void get<Related>(`/threat-feed/related/${kind}/${encodeURIComponent(id)}`, controller.signal).then((value) => { if (!controller.signal.aborted && Array.isArray(value.items)) setData(value); }).catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [id, kind]);
  return <section className="space-y-3 rounded-xl border border-zinc-800 p-5"><h2 className="font-medium">Related intelligence</h2><p className="text-xs text-zinc-500">Stored exact references only; a shared indicator does not establish a shared campaign.</p>{error ? <p role="status">Related links unavailable.</p> : !data ? <p className="text-xs text-zinc-500">Loading related references…</p> : <>{data.items.length ? data.items.map(({ record, reason, supporting_values }) => <div key={`${record.kind}:${record.id}`}><Link href={record.href} className="text-sm text-sky-300 focus-visible:outline">{record.title}</Link><p className="break-all text-xs text-zinc-500">{record.source} · {reason}: {supporting_values.join(", ")}</p></div>) : <p className="text-xs text-zinc-500">No exact stored connections found.</p>}{data.cves.map((cve) => <Link key={cve} className="block text-sm text-sky-300" href={`/threat-feed?tab=poc&cve=${encodeURIComponent(cve)}`}>Find PoC & Tools: {cve}</Link>)}</>}</section>;
}
