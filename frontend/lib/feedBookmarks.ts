export type SavedKind = "news" | "vulnerability" | "ioc";
export type FeedBookmark = { kind: SavedKind; id: string; title: string; href: string; saved_at: string };
const KEY = "threatlens.feed.saved.v1";
export const bookmarkPath = (kind: SavedKind, id: string) => kind === "news" ? `/threat-feed/${encodeURIComponent(id)}` : `/threat-feed/${kind === "ioc" ? "ioc-reports" : "vulnerabilities"}/${encodeURIComponent(id)}`;
const path = bookmarkPath;
function cleanBookmark(value: unknown): FeedBookmark | null {
  if (!value || typeof value !== "object") return null;
  const r = value as Record<string, unknown>;
  if (!["news", "ioc", "vulnerability"].includes(String(r.kind)) || typeof r.id !== "string"
    || !/^[A-Za-z0-9_.:-]{1,200}$/.test(r.id) || typeof r.title !== "string" || r.title.length > 500
    || typeof r.saved_at !== "string" || !Number.isFinite(Date.parse(r.saved_at))) return null;
  const kind = r.kind as SavedKind;
  if (r.href !== path(kind, r.id)) return null;
  return { kind, id: r.id, title: r.title, href: path(kind, r.id), saved_at: r.saved_at };
}
export function savedFeed(): FeedBookmark[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const value = JSON.parse(raw);
      if (value.version !== 1 || !Array.isArray(value.items)) return [];
      return (value.items as unknown[]).map(cleanBookmark).filter((r): r is FeedBookmark => r !== null).slice(-500);
    }
    const migrated: FeedBookmark[] = [];
    for (const [kind, key] of [["news", "threatlens.feed.bookmarks"], ["ioc", "threatlens.feed.iocs.bookmarks"]] as const) {
      let ids: unknown; try { ids = JSON.parse(localStorage.getItem(key) ?? "[]"); } catch { continue; }
      if (Array.isArray(ids)) for (const id of ids) if (typeof id === "string") {
        const item = cleanBookmark({ kind, id, title: "Previously bookmarked report", href: path(kind, id), saved_at: new Date().toISOString() });
        if (item) migrated.push(item);
      }
    }
    const items = migrated.slice(-500); localStorage.setItem(KEY, JSON.stringify({ version: 1, items })); return items;
  } catch { return []; }
}
export function saveFeedBookmark(kind: SavedKind, id: string, title: string): boolean {
  try {
    const items = savedFeed(); const exists = items.some((r) => r.kind === kind && r.id === id);
    const next = items.filter((r) => r.kind !== kind || r.id !== id);
    if (!exists) next.push({ kind, id, title: title.slice(0, 500), href: path(kind, id), saved_at: new Date().toISOString() });
    localStorage.setItem(KEY, JSON.stringify({ version: 1, items: next.slice(-500) }));
    window.dispatchEvent(new Event("feed-bookmarks")); return !exists;
  } catch { throw new Error("Browser bookmark storage is unavailable."); }
}
export function clearFeedBookmarks() { localStorage.setItem(KEY, JSON.stringify({ version: 1, items: [] })); window.dispatchEvent(new Event("feed-bookmarks")); }

export function exportFeedBookmarks() {
  return { format: "threatlens-feed-bookmarks", version: 1, exported_at: new Date().toISOString(), items: savedFeed() };
}
export function parseBookmarkImport(text: string): FeedBookmark[] {
  if (new TextEncoder().encode(text).length > 1_048_576) throw new Error("Bookmark file is too large (maximum 1 MiB).");
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new Error("Invalid bookmark JSON."); }
  if (!raw || typeof raw !== "object") throw new Error("Unsupported bookmark format.");
  const record = raw as Record<string, unknown>;
  if (record.format !== "threatlens-feed-bookmarks" || record.version !== 1 || !Array.isArray(record.items)
    || record.items.length > 500) throw new Error("Unsupported bookmark format or more than 500 entries.");
  const items = record.items.map(cleanBookmark);
  if (items.some((item) => !item)) throw new Error("Invalid bookmark entry or unsafe link. Nothing was imported.");
  return items as FeedBookmark[];
}
export function previewBookmarkMerge(incoming: FeedBookmark[], current = savedFeed()) {
  const existing = new Set(current.map((item) => `${item.kind}:${item.id}`));
  const additions: FeedBookmark[] = [];
  let duplicates = 0;
  for (const item of incoming) {
    const key = `${item.kind}:${item.id}`;
    if (existing.has(key)) duplicates++;
    else { existing.add(key); additions.push(item); }
  }
  const room = Math.max(0, 500 - current.length);
  return { additions: additions.slice(0, room), duplicates, skipped: Math.max(0, additions.length - room) };
}
export function mergeFeedBookmarks(incoming: FeedBookmark[]) {
  const sanitized = parseBookmarkImport(JSON.stringify({ format: "threatlens-feed-bookmarks", version: 1, items: incoming }));
  const current = savedFeed();
  const preview = previewBookmarkMerge(sanitized, current);
  localStorage.setItem(KEY, JSON.stringify({ version: 1, items: [...current, ...preview.additions] }));
  window.dispatchEvent(new Event("feed-bookmarks"));
  return { added: preview.additions.length, duplicates: preview.duplicates, skipped: preview.skipped };
}

export function addFeedBookmarks(kind: SavedKind, items: { id: string; title: string }[]) {
  if (items.length > 100) throw new Error("Select at most 100 reports at a time.");
  const saved_at = new Date().toISOString();
  const incoming = items.map(({ id, title }) => ({ kind, id, title: title.slice(0, 500), href: path(kind, id), saved_at }));
  try { return mergeFeedBookmarks(incoming); }
  catch { throw new Error("Could not save selected bookmarks. Check browser storage and try again."); }
}
