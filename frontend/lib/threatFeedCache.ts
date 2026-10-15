import type { FeedHomeParams, FeedHomeResponse } from "./api/threatFeed";
import { isNewsItem } from "./newsFeed";

const STORAGE_KEY = "threatlens.feed.home.v1";
const SCHEMA_VERSION = 1;
export const FEED_CACHE_FRESH_MS = 5 * 60 * 1000;
export const FEED_CACHE_MAX_MS = 24 * 60 * 60 * 1000;

type StoredFeedHome = {
  version: number;
  key: string;
  savedAt: number;
  response: FeedHomeResponse;
};

export type CachedFeedHome = {
  response: FeedHomeResponse;
  freshness: "fresh" | "stale";
};

export function feedHomeCacheKey(params: FeedHomeParams): string {
  return JSON.stringify({
    query: (params.query ?? "").trim().toLowerCase(),
    topic: params.topic ?? "",
    hours: params.hours ?? null,
    limit_per_region: params.limit_per_region ?? 5,
    sort: params.sort ?? 'newest',
  });
}

export function readFeedHomeCache(params: FeedHomeParams): CachedFeedHome | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const cached = JSON.parse(raw) as StoredFeedHome;
    const age = Date.now() - cached.savedAt;
    if (cached.version !== SCHEMA_VERSION || !Number.isFinite(age) || age < 0 || age > FEED_CACHE_MAX_MS || !cached.response?.summary?.regions || !cached.response?.sections
      || !["global", "malaysia", "southeast_asia"].every((region) => {
        const key = region as keyof FeedHomeResponse["sections"];
        const section = cached.response.sections[key];
        return section && Number.isFinite(section.total) && Array.isArray(section.items) && section.items.length <= 20 && section.items.every(isNewsItem);
      })) {
      localStorage.removeItem(STORAGE_KEY);
      return null;
    }
    if (cached.key !== feedHomeCacheKey(params)) return null;
    return { response: cached.response, freshness: age <= FEED_CACHE_FRESH_MS ? "fresh" : "stale" };
  } catch {
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* Browser storage is optional. */ }
    return null;
  }
}

export function writeFeedHomeCache(params: FeedHomeParams, response: FeedHomeResponse): void {
  const value: StoredFeedHome = {
    version: SCHEMA_VERSION,
    key: feedHomeCacheKey(params),
    savedAt: Date.now(),
    response,
  };
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(value)); } catch { /* Browser storage is optional. */ }
}
