"use client";
import { useEffect, useState } from "react";
import { SearchLoadingIcon } from "@/components/ui/SearchLoading";
export function SearchProgress({ stage, startedAt, cancel }: { stage: string; startedAt: number | null; cancel: () => void }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, []);
  return <section aria-label="Investigation progress" className="space-y-3 rounded-xl border border-sky-500/20 p-3 text-xs text-zinc-400"><div className="flex items-center gap-3"><SearchLoadingIcon /><div><p role="status">{stage}…</p><p className="mt-1">{Math.max(0, Math.floor((now - (startedAt ?? now)) / 1000))}s elapsed</p></div></div><button onClick={cancel} className="text-sky-300 underline focus-visible:outline">Cancel investigation</button><p>Cancellation stops queued work and browser requests. Already-started provider requests may still consume quota.</p></section>;
}
