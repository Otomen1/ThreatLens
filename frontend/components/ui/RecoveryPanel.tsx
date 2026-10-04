"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
export function RecoveryPanel({ message, retained = false, onRetry, consumesQuota = false, retryAt }: { message: string; retained?: boolean; onRetry?: () => void; consumesQuota?: boolean; retryAt?: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { if (!retryAt) return; const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, [retryAt]);
  const allowed = !retryAt || retryAt <= now;
  if (!allowed) return <div role="alert" className="rounded-xl border border-amber-500/30 p-4 text-amber-200">{message} Retry eligible at {new Date(retryAt!).toLocaleTimeString()}.{retained && " Previous results retained."}</div>;
  return <div role="alert" className="space-y-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200"><p>{message}</p>{retained && <p>Previous results are still available below.</p>}{consumesQuota && <p className="text-xs">Retrying an investigation may consume provider quota.</p>}<div className="flex gap-3">{onRetry && <button className="underline focus-visible:outline" onClick={onRetry}>Retry</button>}<Link href="/dashboard" className="underline">Provider diagnostics</Link></div></div>;
}
