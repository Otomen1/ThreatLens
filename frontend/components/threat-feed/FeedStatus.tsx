"use client";

import { useEffect, useState } from "react";
import { get, getUncached } from "@/lib/api/client";

export type Coverage = {
  generated_at: string; next_refresh_at: string | null;
  sources: { id: string; name: string; collection: string; state: string; stale: boolean;
    last_attempt_at: string | null; last_success_at: string | null; pending: number;
    error: string | null; next_eligible_at: string | null }[];
};
const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Not recorded";
let cached: { data: Coverage; savedAt: number } | null = null;
function validCoverage(value: Coverage): boolean {
  const date = (item: unknown) => item === null || (typeof item === "string" && Number.isFinite(Date.parse(item)));
  return !!value && date(value.generated_at) && date(value.next_refresh_at) && Array.isArray(value.sources) && value.sources.length <= 100
    && value.sources.every((source) => source && [source.id, source.name, source.collection, source.state].every((item) => typeof item === "string")
      && typeof source.stale === "boolean" && Number.isInteger(source.pending) && source.pending >= 0
      && [source.last_attempt_at, source.last_success_at, source.next_eligible_at].every(date)
      && (source.error === null || typeof source.error === "string"));
}

export function FeedStatus({ manualPoc = false }: { manualPoc?: boolean }) {
  const [data, setData] = useState<Coverage | null>(null);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const refresh = () => { cached = null; setAttempt((n) => n + 1); };
    window.addEventListener("threat-feed-refreshed", refresh);
    return () => window.removeEventListener("threat-feed-refreshed", refresh);
  }, []);
  useEffect(() => {
    if (manualPoc || !open) return;
    if (!attempt && cached && Date.now() - cached.savedAt < 300000) { setData(cached.data); return; }
    const controller = new AbortController();
    const read = attempt ? getUncached<Coverage> : get<Coverage>;
    void read("/threat-feed/status", controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (!validCoverage(result)) { setError(true); return; }
      cached = { data: result, savedAt: Date.now() }; setData(result); setError(false);
    }).catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [attempt, manualPoc, open]);
  if (manualPoc) return <p className="mt-4 text-xs text-zinc-500">PoC lookups are manual. Freshness follows each source’s checked time, cache age, and stale flag—not the feed collection schedule.</p>;
  return <details onToggle={(event) => setOpen(event.currentTarget.open)} className="mt-4 rounded-xl border border-zinc-800 p-3 text-xs text-zinc-400">
    <summary className="cursor-pointer focus-visible:outline focus-visible:outline-sky-400">Collection freshness and coverage{data ? ` · ${data.sources.filter((s) => s.stale).length} stale · ${data.sources.filter((s) => s.pending > 0).length} pending` : ""}</summary>
    <p role="status" className="mt-3">{error ? "Status could not update; previous status retained." : data ? `Status retrieved ${date(data.generated_at)}. Article dates and browser cache age are separate.` : "Loading source status…"}</p>
    {error && <button className="mt-2 text-sky-300 focus-visible:outline" onClick={() => setAttempt((n) => n + 1)}>Retry source status</button>}
    {data && <><p className="mt-2">Next public refresh eligibility: {date(data.next_refresh_at)}</p><div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{data.sources.map((s) => <section key={`${s.collection}:${s.id}`} className="rounded-lg bg-zinc-900 p-3"><h3 className="text-zinc-200">{s.name} · {s.collection}</h3><p>{s.state.replaceAll("_", " ")}{s.stale ? " · Stale (over eight hours)" : ""}{s.pending ? ` · ${s.pending} pending` : ""}</p><p>Last attempt: {date(s.last_attempt_at)}</p><p>Last success: {date(s.last_success_at)}</p>{s.error && <p className="text-amber-300">{s.error}</p>}<p>Eligible: {date(s.next_eligible_at)}</p></section>)}</div></>}
    <p className="mt-3">Partial or failed sources do not imply complete coverage. Previously collected records remain available.</p>
  </details>;
}
