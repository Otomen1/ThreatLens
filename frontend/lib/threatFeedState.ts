import type { FeedRegion } from "./api/threatFeed";
import { markFeedRead } from "./feedDisplay";

const key = (name: string) => `threatlens.feed.${name}`;
export function viewedIds(): Set<string> { try { return new Set(JSON.parse(localStorage.getItem(key("viewed")) ?? "[]") as string[]); } catch { return new Set(); } }
export function markViewed(id: string) { markFeedRead("news", id); }
export function markRegionSeen(region: FeedRegion) { try { localStorage.setItem(key(`seen.${region}`), new Date().toISOString()); window.dispatchEvent(new Event("threat-feed-state")); } catch { /* Optional reading state. */ } }
export function regionSeen(region: FeedRegion) { try { return localStorage.getItem(key(`seen.${region}`)); } catch { return null; } }
export function bookmarks(): Set<string> { try { return new Set(JSON.parse(localStorage.getItem(key("bookmarks")) ?? "[]") as string[]); } catch { return new Set(); } }
export function toggleBookmark(id: string) { const values = bookmarks(); values.has(id) ? values.delete(id) : values.add(id); localStorage.setItem(key("bookmarks"), JSON.stringify([...values])); return values.has(id); }
