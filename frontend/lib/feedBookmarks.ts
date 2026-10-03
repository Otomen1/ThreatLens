export type SavedKind = "news" | "vulnerability" | "ioc";
export type FeedBookmark = { kind: SavedKind; id: string; title: string; href: string; saved_at: string };
const KEY = "threatlens.feed.saved.v1";
const path = (kind: SavedKind, id: string) => kind === "news" ? `/threat-feed/${encodeURIComponent(id)}` : `/threat-feed/${kind === "ioc" ? "ioc-reports" : "vulnerabilities"}/${encodeURIComponent(id)}`;
export function savedFeed(): FeedBookmark[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const value = JSON.parse(raw);
      if (value.version !== 1 || !Array.isArray(value.items)) return [];
      return value.items.filter((r: FeedBookmark) => r && ["news", "ioc", "vulnerability"].includes(r.kind) && typeof r.id === "string" && typeof r.title === "string" && r.href === path(r.kind, r.id) && Number.isFinite(Date.parse(r.saved_at))).slice(-500);
    }
    const migrated: FeedBookmark[] = [];
    for (const [kind, key] of [["news", "threatlens.feed.bookmarks"], ["ioc", "threatlens.feed.iocs.bookmarks"]] as const) {
      let ids: unknown; try { ids = JSON.parse(localStorage.getItem(key) ?? "[]"); } catch { continue; }
      if (Array.isArray(ids)) for (const id of ids) if (typeof id === "string") migrated.push({ kind, id, title: "Previously bookmarked report", href: path(kind, id), saved_at: new Date().toISOString() });
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
  } catch { return false; }
}
export function clearFeedBookmarks() { try { localStorage.setItem(KEY, JSON.stringify({ version: 1, items: [] })); window.dispatchEvent(new Event("feed-bookmarks")); } catch { /* Optional storage. */ } }
