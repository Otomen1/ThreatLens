"use client";
import { useEffect, useState } from "react";
export function SearchProgress({ stage, startedAt, cancel }: { stage: string; startedAt: number | null; cancel: () => void }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, []);
  return <section aria-label="Investigation progress" className="space-y-2 rounded-xl border border-sky-500/20 p-3 text-xs text-zinc-400"><p role="status">{stage} · {Math.max(0, Math.floor((now - (startedAt ?? now)) / 1000))}s elapsed</p><div role="progressbar" aria-label={stage} className="h-1 overflow-hidden rounded bg-zinc-800"><div className="h-full w-1/3 animate-pulse bg-sky-500 motion-reduce:animate-none" /></div><button onClick={cancel} className="text-sky-300 underline focus-visible:outline">Cancel investigation</button><p>Cancellation stops queued work and browser requests. Already-started provider requests may still consume quota.</p></section>;
}
