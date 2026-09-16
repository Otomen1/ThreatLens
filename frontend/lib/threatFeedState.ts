import type { FeedRegion } from "./api/threatFeed";

const key = (name: string) => `threatlens.feed.${name}`;
export function viewedIds(): Set<string> { try { return new Set(JSON.parse(localStorage.getItem(key("viewed")) ?? "[]") as string[]); } catch { return new Set(); } }
export function markViewed(id: string) { const ids = viewedIds(); ids.add(id); localStorage.setItem(key("viewed"), JSON.stringify([...ids].slice(-500))); }
export function markRegionSeen(region: FeedRegion) { localStorage.setItem(key(`seen.${region}`), new Date().toISOString()); window.dispatchEvent(new Event("threat-feed-state")); }
export function regionSeen(region: FeedRegion) { return localStorage.getItem(key(`seen.${region}`)); }
export function bookmarks(): Set<string> { try { return new Set(JSON.parse(localStorage.getItem(key("bookmarks")) ?? "[]") as string[]); } catch { return new Set(); } }
export function toggleBookmark(id: string) { const values = bookmarks(); values.has(id) ? values.delete(id) : values.add(id); localStorage.setItem(key("bookmarks"), JSON.stringify([...values])); return values.has(id); }
