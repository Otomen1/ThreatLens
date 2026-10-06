"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { clearFeedBookmarks, savedFeed, saveFeedBookmark, exportFeedBookmarks, parseBookmarkImport,
  previewBookmarkMerge, mergeFeedBookmarks, type FeedBookmark, type SavedKind } from "@/lib/feedBookmarks";
import { checkFeedBookmarks, type BookmarkAvailability } from "@/lib/api/threatFeed";
import { triggerJsonDownload } from "@/lib/download";
import { useToast } from "@/components/ui/ToastProvider";
import { feedControl } from "./FeedWorkflow";
import { useListFilters } from "@/hooks/useListFilters";

const SAVED_FILTERS = { saved_type: ["", "news", "vulnerability", "ioc"], page: [] };

export function BookmarkButton({ kind, id, title }: { kind: SavedKind; id: string; title: string }) {
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(false);
  const { notify } = useToast();
  useEffect(() => {
    const read = () => setSaved(savedFeed().some((r) => r.kind === kind && r.id === id));
    read(); window.addEventListener("feed-bookmarks", read);
    return () => window.removeEventListener("feed-bookmarks", read);
  }, [id, kind]);
  return <span><button className={feedControl} aria-pressed={saved} onClick={() => {
    try { const next = saveFeedBookmark(kind, id, title); setSaved(next); setError(false); notify(next ? "Bookmark saved in this browser." : "Bookmark removed."); }
    catch { setError(true); }
  }}>{saved ? "Remove from Saved" : "Save locally"}</button>{error && <span role="status" className="ml-2 text-xs text-amber-200">Browser storage unavailable; bookmark unchanged.</span>}</span>;
}

export function SavedFeed() {
  const [items, setItems] = useState<FeedBookmark[]>([]);
  const [confirm, setConfirm] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [availability, setAvailability] = useState<Map<string, BookmarkAvailability>>(new Map());
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [incoming, setIncoming] = useState<FeedBookmark[] | null>(null);
  const [message, setMessage] = useState("");
  const { notify } = useToast();
  const { filters, update, hydrated } = useListFilters(SAVED_FILTERS);
  const kind = filters.saved_type;
  const visible = useMemo(() => items.filter((r) => !kind || r.kind === kind), [items, kind]);
  const page = Math.min(Math.max(1, Math.floor(Number(filters.page) || 1)), Math.max(1, Math.ceil(visible.length / 20)));
  const keys = JSON.stringify(visible.slice((page - 1) * 20, page * 20).map(({ kind, id }) => ({ kind, id })));
  useEffect(() => {
    const load = () => { setItems(savedFeed()); setLoaded(true); };
    load(); window.addEventListener("feed-bookmarks", load); window.addEventListener("storage", load);
    return () => { window.removeEventListener("feed-bookmarks", load); window.removeEventListener("storage", load); };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    const entries = JSON.parse(keys) as { kind: SavedKind; id: string }[];
    if (!entries.length) { setChecking(false); return; }
    setChecking(true);
    void checkFeedBookmarks(entries, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (!Array.isArray(result) || result.length !== entries.length) throw new Error("Incomplete availability check");
      setAvailability(new Map(result.map((r) => [`${r.kind}:${r.id}`, r]))); setError(false);
    }).catch(() => { if (!controller.signal.aborted) setError(true); })
      .finally(() => { if (!controller.signal.aborted) setChecking(false); });
    return () => controller.abort();
  }, [keys, attempt]);
  async function importFile(file?: File) {
    setIncoming(null); setMessage("");
    if (!file) return;
    if (file.size > 1_048_576) { setMessage("Bookmark file is too large (maximum 1 MiB)."); return; }
    try { setIncoming(parseBookmarkImport(await file.text())); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Couldn't read bookmark file."); }
  }
  function confirmImport() {
    if (!incoming) return;
    try {
      const result = mergeFeedBookmarks(incoming);
      setMessage(`${result.added} added · ${result.duplicates} duplicates kept · ${result.skipped} skipped at the 500-bookmark limit.`);
      notify("Bookmarks imported locally."); setIncoming(null);
    } catch { setMessage("Couldn't save bookmarks in this browser. Existing bookmarks are unchanged."); }
  }
  const preview = incoming ? previewBookmarkMerge(incoming, items) : null;
  return <main data-list-ready={hydrated && loaded} className="mx-auto max-w-6xl space-y-4 px-4 py-8">
    <h2 className="text-xl">Saved intelligence</h2>
    <p className="text-xs text-zinc-500">Browser-local. No PoC results, full articles, IOC lists, or credentials are stored or exported here.</p>
    <div className="flex flex-wrap items-center gap-3">
      <select aria-label="Saved record type" className={`${feedControl} bg-zinc-950`} value={kind} onChange={(e) => update("saved_type", e.target.value)}><option value="">All types</option><option value="news">News</option><option value="vulnerability">Vulnerabilities</option><option value="ioc">IOC Reports</option></select>
      <button className={feedControl} onClick={() => setConfirm(true)}>Clear all saved</button>
      <button className={feedControl} onClick={() => { try { triggerJsonDownload("threatlens-bookmarks.json", exportFeedBookmarks()); notify("Bookmarks exported."); } catch { setMessage("Couldn't export bookmarks."); } }}>Export bookmarks</button>
      <label className={`${feedControl} cursor-pointer focus-within:outline focus-within:outline-sky-400`}>Import bookmarks<input aria-label="Import bookmarks" className="sr-only" type="file" accept=".json,application/json" onChange={(e) => { void importFile(e.target.files?.[0]); e.target.value = ""; }} /></label>
    </div>
    {confirm && <div role="alert" className="flex flex-wrap gap-3"><p>Remove all bookmarks from this browser?</p><button className={feedControl} onClick={() => { try { clearFeedBookmarks(); setConfirm(false); notify("Bookmarks cleared from this browser."); } catch { setMessage("Browser storage unavailable; bookmarks were not cleared."); } }}>Confirm clear</button><button className={feedControl} onClick={() => setConfirm(false)}>Cancel</button></div>}
    {preview && <div className="space-y-3 rounded-xl border border-sky-900 p-4" role="status"><p>Import preview: {preview.additions.length} new · {preview.duplicates} duplicates · {preview.skipped} beyond the limit. Existing bookmarks will not be removed or replaced.</p><button className={feedControl} onClick={confirmImport}>Confirm bookmark import</button><button className={`${feedControl} ml-2`} onClick={() => setIncoming(null)}>Cancel import</button></div>}
    {message && <p role="status" className="text-sm text-amber-200">{message}</p>}
    <p role="status" className="min-h-5 text-xs text-zinc-400">{checking ? "Checking saved availability…" : error ? "Availability couldn't update. Bookmarks and previous checks are retained." : ""}</p>
    {error && !checking && <button className={feedControl} onClick={() => setAttempt((n) => n + 1)}>Retry availability</button>}
    {visible.slice((page - 1) * 20, page * 20).map((item) => {
      const result = availability.get(`${item.kind}:${item.id}`);
      return <div key={`${item.kind}:${item.id}`} className="rounded-lg border border-zinc-800 p-4"><Link href={item.href} className="text-sky-300 focus-visible:outline">{result?.title ?? item.title}</Link><p className="mt-1 text-xs text-zinc-500">{item.kind} · {result ? result.available ? "Available" : "Unavailable or expired; bookmark retained" : "Availability not checked"} · Saved {new Date(item.saved_at).toLocaleDateString()}</p><button className={`${feedControl} mt-2`} onClick={() => { try { saveFeedBookmark(item.kind, item.id, item.title); notify("Bookmark removed."); } catch { setMessage("Browser storage unavailable; bookmark unchanged."); } }}>Remove</button></div>;
    })}
    <nav aria-label="Saved pagination" className="flex gap-3"><button className={feedControl} disabled={page <= 1} onClick={() => update("page", String(page - 1))}>Previous saved</button><span>Page {page}</span><button className={feedControl} disabled={page * 20 >= visible.length} onClick={() => update("page", String(page + 1))}>Next saved</button></nav>
    {!visible.length && <p className="text-zinc-500">{items.length ? "No saved intelligence matches this type." : "No saved intelligence yet."}</p>}
  </main>;
}
