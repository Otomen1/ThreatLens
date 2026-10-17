"use client";

import { useEffect, useRef, useState } from "react";
import { addFeedBookmarks, type SavedKind } from "@/lib/feedBookmarks";
import { markFeedReadMany } from "@/lib/feedDisplay";
import type { FeedSelection } from "@/hooks/useFeedSelection";
import { useToast } from "@/components/ui/ToastProvider";

const button = "rounded-lg border border-zinc-700 px-3 py-2 text-xs hover:border-sky-500 focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40";
export type FeedRowSelection = { selection: FeedSelection; disabled: boolean };

export function FeedRowCheckbox({ id, title, selection, disabled }: FeedRowSelection & { id: string; title: string }) {
  return <input type="checkbox" aria-label={`Select ${title}`} checked={selection.selected.has(id)} disabled={disabled} onChange={() => selection.toggle(id)} className="mr-2 size-4 align-middle accent-sky-500 focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40" />;
}

export function FeedBulkActions({ kind, items, selection, disabled }: FeedRowSelection & { kind: SavedKind; items: { id: string; title: string }[] }) {
  const { notify } = useToast();
  const [message, setMessage] = useState("");
  const checkbox = useRef<HTMLInputElement>(null);
  const count = selection.selected.size;
  useEffect(() => { if (checkbox.current) checkbox.current.indeterminate = count > 0 && count < items.length; }, [count, items.length]);
  function perform(action: "read" | "save") {
    if (disabled || !count) return;
    try {
      const chosen = items.filter((item) => selection.selected.has(item.id));
      let result: string;
      if (action === "read") {
        const value = markFeedReadMany(kind, chosen.map((item) => item.id));
        result = `${value.marked} marked read · ${value.alreadyRead} already read.`;
      } else {
        const value = addFeedBookmarks(kind, chosen);
        result = `${value.added} saved · ${value.duplicates} already saved${value.skipped ? ` · ${value.skipped} skipped (500-bookmark limit)` : ""}.`;
      }
      setMessage(result); notify(result);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Browser storage is unavailable. Try again.");
      notify("The browser-local action could not be completed.", "error");
    }
  }
  return <section aria-label="Report selection" className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3 text-xs text-zinc-400">
    <div className="flex flex-wrap items-center gap-3">
      <label className="inline-flex items-center gap-2"><input ref={checkbox} type="checkbox" aria-label="Select current page" disabled={disabled || !items.length} checked={Boolean(items.length && count === items.length)} onChange={selection.toggleAll} className="size-4 accent-sky-500 focus-visible:outline focus-visible:outline-sky-400" />Select current page</label>
      <span>{count} selected</span>
      <button type="button" className={button} disabled={disabled || !count} onClick={() => perform("read")}>Mark selected read</button>
      <button type="button" className={button} disabled={disabled || !count} onClick={() => perform("save")}>Save selected</button>
      <button type="button" className={button} disabled={!count} onClick={() => { selection.clear(); setMessage(""); }}>Clear selection</button>
    </div>
    <p className="mt-2 text-zinc-500">Browser-local · Current page only. Saving adds bookmarks without removing existing ones.{disabled && " Selection is paused while loading or showing previous filters."}</p>
    <p role="status" aria-live="polite" className="mt-2 min-h-4 text-amber-200">{message}</p>
  </section>;
}
