// Public compact lists only; never private results or article details.
export const FEED_CACHE_FRESH_MS = 5 * 60 * 1000;
export const FEED_CACHE_MAX_MS = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 8;
const MAX_BYTES = 1024 * 1024;
type Entry<T> = { key: string; savedAt: number; response: T };
export type CachedFeed<T> = { response: T; freshness: "fresh" | "stale" };
export function clearPublicFeedCache(storageKey: string) {
  try { localStorage.removeItem(storageKey); } catch { /* Optional browser storage. */ }
}
function entries<T>(storageKey: string, valid: (value: unknown) => value is T): Entry<T>[] {
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return [];
    if (raw.length * 2 > MAX_BYTES) { clearPublicFeedCache(storageKey); return []; }
    const stored = JSON.parse(raw);
    // Import old caches without resetting their age.
    const candidates: unknown = stored.version === 1 && !stored.entries ? [stored] : stored.entries;
    if (![1, 2].includes(stored.version) || !Array.isArray(candidates) || candidates.length > MAX_ENTRIES) {
      clearPublicFeedCache(storageKey); return [];
    }
    const now = Date.now();
    const result = candidates.filter((value): value is Entry<T> => {
      if (!value || typeof value !== "object") return false;
      const entry = value as Entry<unknown>;
      return typeof entry.key === "string" && entry.key.length <= 2000 && Number.isFinite(entry.savedAt)
        && now >= entry.savedAt && now - entry.savedAt <= FEED_CACHE_MAX_MS && valid(entry.response);
    });
    if (!result.length) clearPublicFeedCache(storageKey);
    return result;
  } catch { clearPublicFeedCache(storageKey); return []; }
}
export function readPublicFeedCache<T>(storageKey: string, key: string, valid: (value: unknown) => value is T): CachedFeed<T> | null {
  const entry = entries(storageKey, valid).find((entry) => entry.key === key);
  return entry ? { response: entry.response, freshness: Date.now() - entry.savedAt <= FEED_CACHE_FRESH_MS ? "fresh" : "stale" } : null;
}
export function writePublicFeedCache<T>(storageKey: string, key: string, response: T, valid: (value: unknown) => value is T) {
  if (!valid(response)) return;
  const values = [{ key, response, savedAt: Date.now() }, ...entries(storageKey, valid).filter((entry) => entry.key !== key)].slice(0, MAX_ENTRIES);
  try {
    while (values.length && JSON.stringify({ version: 2, entries: values }).length * 2 > MAX_BYTES) values.pop();
    if (values.length) localStorage.setItem(storageKey, JSON.stringify({ version: 2, entries: values }));
  } catch { /* Network reads still work without browser storage. */ }
}
