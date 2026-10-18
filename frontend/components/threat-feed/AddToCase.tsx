"use client";

import Link from "next/link";
import { useEffect, useId, useRef, useState } from "react";
import { useOwnerSession } from "@/components/OwnerSessionProvider";
import { useToast } from "@/components/ui/ToastProvider";
import { attachFeedToCase, listCases, type Case, type CaseFeedKind } from "@/lib/api/cases";
import { ApiError } from "@/lib/api/client";

const control = "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40";

export function AddToCase({ kind, id }: { kind: CaseFeedKind; id: string }) {
  const session = useOwnerSession();
  if (session.status !== "owner" || !session.userId) return <p className="text-xs text-zinc-500">{session.status === "checking" ? "Checking sign-in…" : <><Link href="/login" className="text-sky-300 hover:underline">Sign in</Link> as the owner to add this reference to a Case.</>}</p>;
  // Remount and abort private work on any identity or source-record change.
  return <CasePicker key={`${session.userId}:${kind}:${id}`} kind={kind} id={id} />;
}

function CasePicker({ kind, id }: { kind: CaseFeedKind; id: string }) {
  const [open, setOpen] = useState(false);
  const [cases, setCases] = useState<Case[] | null>(null);
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [retryable, setRetryable] = useState(true);
  const [retryAt, setRetryAt] = useState<number | null>(null);
  const [saved, setSaved] = useState<Case | null>(null);
  const request = useRef<AbortController | null>(null);
  const label = useId();
  const { notify } = useToast();
  useEffect(() => () => request.current?.abort(), []);
  useEffect(() => {
    if (retryAt === null) return;
    const timer = window.setTimeout(() => setRetryAt(null), Math.max(0, retryAt - Date.now()));
    return () => window.clearTimeout(timer);
  }, [retryAt]);

  function fail(reason: unknown) {
    setRetryable(!(reason instanceof ApiError) || reason.retryable !== false);
    setRetryAt(reason instanceof ApiError && reason.retryAt && reason.retryAt > Date.now() ? reason.retryAt : null);
    setError(reason instanceof Error ? reason.message : "Could not complete this action. Your Case is unchanged.");
  }
  async function load() {
    if (busy || (retryAt !== null && retryAt > Date.now())) { setOpen(true); return; }
    setOpen(true); setError(""); setBusy(true);
    request.current?.abort(); const controller = new AbortController(); request.current = controller;
    try {
      const result = await listCases({}, controller.signal);
      if (controller.signal.aborted) return;
      setCases(result.cases); setSelected("");
    } catch (reason) { if (!controller.signal.aborted) fail(reason); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }
  async function attach() {
    if (!selected || busy || (retryAt !== null && retryAt > Date.now())) return;
    setError(""); setBusy(true);
    request.current?.abort(); const controller = new AbortController(); request.current = controller;
    try {
      const record = await attachFeedToCase(selected, kind, id, controller.signal);
      if (controller.signal.aborted) return;
      setSaved(record); setCases((records) => records?.map((item) => item.id === record.id ? record : item) ?? null); setOpen(false); notify("Feed reference saved to Case.");
    } catch (reason) { if (!controller.signal.aborted) fail(reason); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }
  const chosen = cases?.find((record) => record.id === selected);
  const attached = chosen?.feed_references?.some((ref) => ref.kind === kind && ref.id === id);
  const full = (chosen?.feed_references?.length ?? 0) >= 100;
  return <div className="space-y-3">
    <div className="flex flex-wrap items-center gap-3"><button type="button" className={control} aria-expanded={open} onClick={() => { if (open) setOpen(false); else if (cases) setOpen(true); else void load(); }}>Add to Case</button>{saved && <p role="status" className="text-xs text-emerald-300">Saved to database · <Link className="underline" href={`/cases/${saved.id}`}>Open {saved.title}</Link></p>}</div>
    {open && <section aria-label="Add feed reference to Case" className="space-y-3 rounded-xl border border-zinc-700 bg-zinc-900 p-4">
      <p className="text-xs leading-5 text-zinc-400">Attach the title and source attribution to an existing Case. No investigation runs and no indicators are imported. Feed details may expire; the saved reference remains source-reported and unverified.</p>
      {error && <div role="alert" className="space-y-2 text-sm text-red-300"><p>{error}</p><p className="text-xs text-zinc-400">If a save response was interrupted, check the Case or retry the same attachment—it cannot create a duplicate.</p>{cases === null && retryable && <button type="button" disabled={busy || retryAt !== null} className={control} onClick={() => void load()}>Retry Case list</button>}</div>}
      {retryAt !== null && <p role="status" className="text-xs text-amber-200">Retry available after {new Date(retryAt).toLocaleTimeString()}. No automatic retry.</p>}
      {full && !attached && <p className="text-xs text-amber-200">This Case has 100 feed references. Remove one in the Case first.</p>}
      {busy && cases === null ? <p role="status" className="text-xs text-zinc-400">Loading your Cases…</p> : cases?.length === 0 ? <div className="space-y-3"><p className="text-sm text-zinc-400">No Cases yet. <Link className="text-sky-300 underline" href="/cases">Create a Case</Link>, then reload this list.</p><button type="button" disabled={busy || retryAt !== null} className={control} onClick={() => void load()}>Reload Cases</button></div> : cases && <>
        <label htmlFor={label} className="block text-xs text-zinc-300">Choose an existing Case</label>
        <select id={label} className={`${control} w-full`} value={selected} disabled={busy} onChange={(event) => { setSelected(event.target.value); setError(""); }}><option value="">Select a Case…</option>{cases.map((record) => <option key={record.id} value={record.id}>{record.title} · {record.status.replaceAll("_", " ")}</option>)}</select>
        <div className="flex flex-wrap items-center gap-3"><button type="button" className={control} onClick={() => void attach()} disabled={!selected || busy || attached || full || retryAt !== null || (!!error && !retryable)}>{busy ? "Saving reference…" : attached ? "Already attached" : "Confirm add to Case"}</button>{attached && <Link className="text-xs text-sky-300 underline" href={`/cases/${selected}`}>Open Case</Link>}<button type="button" disabled={busy} className={control} onClick={() => setOpen(false)}>Cancel</button><button type="button" disabled={busy || retryAt !== null} className={control} onClick={() => void load()}>Reload Cases</button></div>
      </>}
    </section>}
  </div>;
}
