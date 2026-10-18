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
  const container = useRef<HTMLElement>(null);
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
  return <section ref={container} tabIndex={-1} aria-label="Report selection" className="rounded-lg border border-zinc-800 px-3 py-2 text-xs text-zinc-400">
    <div className="flex flex-wrap items-center gap-3">
      <label className="inline-flex items-center gap-2"><input ref={checkbox} type="checkbox" aria-label="Select current page" disabled={disabled || !items.length} checked={Boolean(items.length && count === items.length)} onChange={selection.toggleAll} className="size-4 accent-sky-500 focus-visible:outline focus-visible:outline-sky-400" />Select current page</label>
      <span aria-live="polite">{count} selected</span>
      {count > 0 && <div className="feed-selection-actions flex flex-wrap gap-2"><button type="button" className={button} disabled={disabled} onClick={() => perform("read")}>Mark selected read</button>
      <button type="button" className={button} disabled={disabled} onClick={() => perform("save")}>Save selected</button>
      <button type="button" className={button} onClick={() => { selection.clear(); setMessage(""); if (checkbox.current?.disabled) container.current?.focus(); else checkbox.current?.focus(); }}>Clear selection</button></div>}
    </div>
    {(count > 0 || disabled) && <p className="mt-2 text-zinc-400">Browser-local · Current page only.{count > 0 && " Existing bookmarks are kept."}{disabled && " Selection is paused while loading or showing previous filters."}</p>}
    <p role="status" aria-live="polite" className={message ? "mt-2 text-amber-200" : "sr-only"}>{message}</p>
  </section>;
}
