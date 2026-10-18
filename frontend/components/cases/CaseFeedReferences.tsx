"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { removeFeedFromCase, type Case } from "@/lib/api/cases";
import { bookmarkPath } from "@/lib/feedBookmarks";
import { useToast } from "@/components/ui/ToastProvider";

function safeSource(value: string): string | null {
  try { const url = new URL(value); return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password ? url.href : null; }
  catch { return null; }
}

export function CaseFeedReferences({ record, onChange }: { record: Case; onChange: (value: Case) => void }) {
  const [confirm, setConfirm] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);
  const { notify } = useToast();
  useEffect(() => () => request.current?.abort(), []);
  const references = record.feed_references ?? [];
  return <section aria-label="Feed references" className="space-y-3 rounded-2xl border border-zinc-800 bg-zinc-900 p-5">
    <h2 className="text-sm font-semibold">Feed references <span className="text-xs font-normal text-zinc-500">({references.length}/100)</span></h2>
    <p className="text-xs leading-5 text-zinc-400">Saved to database · Source snapshots, not verified intelligence. Original feed details may expire after retention; source links and attribution remain here. Included in personal backups.</p>
    {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
    {!references.length ? <p className="text-sm text-zinc-500">Open a News, Vulnerability or IOC report in Threat Feed and choose Add to Case.</p> : <ul className="space-y-3">{references.map((ref) => {
      const key = `${ref.kind}:${ref.id}`;
      return <li key={key} className="space-y-2 rounded-xl border border-zinc-800 bg-zinc-950/50 p-3">
        <Link href={bookmarkPath(ref.kind, ref.id)} className="break-words text-sm text-sky-300 hover:underline">{ref.title}</Link>
        <p className="text-xs text-zinc-500">{ref.kind === "ioc" ? "IOC report" : ref.kind} · Attached {new Date(ref.attached_at).toLocaleString()} · Source-reported · Unverified</p>
        {ref.attribution && <p className="break-words text-xs text-zinc-400">{ref.attribution}{ref.license && ` · ${ref.license}`}</p>}
        <div className="flex flex-wrap gap-3">{ref.sources.map((source, index) => { const url = safeSource(source.url); return url ? <a key={`${url}:${index}`} href={url} target="_blank" rel="noreferrer" className="text-xs text-sky-300 hover:underline">{source.name} ↗</a> : null; })}</div>
        {confirm === key ? <div className="flex flex-wrap items-center gap-3 text-xs"><span>Remove this reference only?</span><button type="button" disabled={busy} className="rounded border border-red-900 px-3 py-2 text-red-300" onClick={async () => {
          setBusy(true); setError(""); const controller = new AbortController(); request.current = controller;
          try { const updated = await removeFeedFromCase(record.id, ref.kind, ref.id, controller.signal); if (!controller.signal.aborted) { onChange(updated); setConfirm(null); notify("Reference removed. Feed and investigations unchanged."); } }
          catch (reason) { if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Could not remove the reference."); }
          finally { if (!controller.signal.aborted) setBusy(false); }
        }}>{busy ? "Removing…" : "Confirm remove reference"}</button><button type="button" disabled={busy} className="rounded border border-zinc-700 px-3 py-2" onClick={() => setConfirm(null)}>Keep reference</button></div> : <button type="button" disabled={busy} className="rounded border border-zinc-700 px-3 py-2 text-xs text-zinc-400" onClick={() => setConfirm(key)}>Remove reference</button>}
      </li>;
    })}</ul>}
  </section>;
}
