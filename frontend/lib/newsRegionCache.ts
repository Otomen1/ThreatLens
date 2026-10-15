import type { FeedList } from "./api/threatFeed";
import { FEED_CACHE_FRESH_MS, FEED_CACHE_MAX_MS } from "./threatFeedCache";
import { isNewsItem } from "./newsFeed";

const KEY = "threatlens.feed.news-regions.v1";
type Entry = { key: string; savedAt: number; response: FeedList };
function validEntry(value: unknown): value is Entry {
  if (!value || typeof value !== "object") return false;
  const item = value as Entry;
  const response = item.response;
  return typeof item.key === "string" && Number.isFinite(item.savedAt) && item.savedAt <= Date.now()
    && Date.now() - item.savedAt <= FEED_CACHE_MAX_MS && !!response
    && Number.isInteger(response.total) && response.total >= 0 && Number.isInteger(response.page) && response.page > 0
    && response.page_size === 10 && Array.isArray(response.items) && response.items.length <= 10
    && response.items.every(isNewsItem);
}
function entries(): Entry[] {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) ?? "null");
    if (!raw) return [];
    if (raw.version !== 1 || !Array.isArray(raw.entries) || raw.entries.length > 3) { clearNewsRegionCache(); return []; }
    const valid = raw.entries.filter(validEntry);
    if (valid.length !== raw.entries.length) {
      if (valid.length) localStorage.setItem(KEY, JSON.stringify({ version: 1, entries: valid }));
      else clearNewsRegionCache();
    }
    return valid;
  } catch { clearNewsRegionCache(); return []; }
}
export function readNewsRegionCache(key: string) {
  const item = entries().find((entry) => entry.key === key);
  return item ? { response: item.response, freshness: Date.now() - item.savedAt <= FEED_CACHE_FRESH_MS ? "fresh" : "stale" } : null;
}
export function writeNewsRegionCache(key: string, response: FeedList) {
  const entry = { key, response, savedAt: Date.now() };
  if (!validEntry(entry)) return;
  try { localStorage.setItem(KEY, JSON.stringify({ version: 1, entries: [entry, ...entries().filter((old) => old.key !== key)].slice(0, 3) })); } catch { /* Optional public metadata cache. */ }
}
export function clearNewsRegionCache() {
  try { localStorage.removeItem(KEY); } catch { /* Browser storage can be unavailable. */ }
}
