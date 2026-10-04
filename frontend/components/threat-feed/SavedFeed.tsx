"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { get } from "@/lib/api/client";
import { clearFeedBookmarks, savedFeed, saveFeedBookmark, type FeedBookmark, type SavedKind } from "@/lib/feedBookmarks";
import { feedControl } from "./FeedWorkflow";

export function BookmarkButton({ kind, id, title }: { kind: SavedKind; id: string; title: string }) {
  const [saved, setSaved] = useState(false);
  useEffect(() => { const read = () => setSaved(savedFeed().some((r) => r.kind === kind && r.id === id)); read(); window.addEventListener("feed-bookmarks", read); return () => window.removeEventListener("feed-bookmarks", read); }, [id, kind]);
  return <button className={feedControl} aria-pressed={saved} onClick={() => setSaved(saveFeedBookmark(kind, id, title))}>{saved ? "Remove from Saved" : "Save locally"}</button>;
}
function SavedRow({ item, remove }: { item: FeedBookmark; remove: () => void }) {
  const [state, setState] = useState("Checking availability…");
  const [title, setTitle] = useState(item.title);
  useEffect(() => { const controller = new AbortController(); const endpoint = item.kind === "news" ? "items" : item.kind === "ioc" ? "ioc-reports" : "vulnerabilities";
    void get<{ title?: string; report?: { title: string } }>(`/threat-feed/${endpoint}/${encodeURIComponent(item.id)}`, controller.signal).then((record) => { if (!controller.signal.aborted) { setTitle(record.report?.title ?? record.title ?? item.title); setState("Available"); } }).catch(() => { if (!controller.signal.aborted) setState("Unavailable or expired; bookmark retained"); });
    return () => controller.abort();
  }, [item]);
  return <div className="rounded-lg border border-zinc-800 p-4"><Link href={item.href} className="text-sky-300 focus-visible:outline">{title}</Link><p className="mt-1 text-xs text-zinc-500">{item.kind} · {state} · Saved {new Date(item.saved_at).toLocaleDateString()}</p><button className={`${feedControl} mt-2`} onClick={() => { saveFeedBookmark(item.kind, item.id, item.title); remove(); }}>Remove</button></div>;
}
export function SavedFeed() {
  const [items, setItems] = useState<FeedBookmark[]>([]); const [kind, setKind] = useState(""); const [confirm, setConfirm] = useState(false); const [page, setPage] = useState(1);
  const load = () => setItems(savedFeed());
  useEffect(() => { load(); }, []);
  const visible = items.filter((r) => !kind || r.kind === kind);
  return <main className="mx-auto max-w-6xl space-y-4 px-4 py-8"><h2 className="text-xl">Saved intelligence</h2><p className="text-xs text-zinc-500">Browser-local. No PoC results, full articles, or IOC lists are stored here.</p><select aria-label="Saved record type" className={`${feedControl} bg-zinc-950`} value={kind} onChange={(e) => { setKind(e.target.value); setPage(1); }}><option value="">All types</option><option value="news">News</option><option value="vulnerability">Vulnerabilities</option><option value="ioc">IOC Reports</option></select><button className={feedControl} onClick={() => setConfirm(true)}>Clear all saved</button>{confirm && <div role="alert" className="flex flex-wrap gap-3"><p>Remove all bookmarks from this browser?</p><button className={feedControl} onClick={() => { clearFeedBookmarks(); load(); setConfirm(false); }}>Confirm clear</button><button className={feedControl} onClick={() => setConfirm(false)}>Cancel</button></div>}{visible.slice((page - 1) * 20, page * 20).map((item) => <SavedRow key={`${item.kind}:${item.id}`} item={item} remove={load} />)}<nav aria-label="Saved pagination" className="flex gap-3"><button className={feedControl} disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous saved</button><span>Page {page}</span><button className={feedControl} disabled={page * 20 >= visible.length} onClick={() => setPage(page + 1)}>Next saved</button></nav>{!items.length && <p className="text-zinc-500">No saved intelligence yet.</p>}</main>;
}
