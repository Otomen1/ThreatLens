import type { FeedHomeParams, FeedHomeResponse } from "./api/threatFeed";

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
  });
}

export function readFeedHomeCache(params: FeedHomeParams): CachedFeedHome | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const cached = JSON.parse(raw) as StoredFeedHome;
    const age = Date.now() - cached.savedAt;
    if (cached.version !== SCHEMA_VERSION || cached.key !== feedHomeCacheKey(params) || age > FEED_CACHE_MAX_MS || !cached.response?.summary || !cached.response?.sections) {
      localStorage.removeItem(STORAGE_KEY);
      return null;
    }
    return { response: cached.response, freshness: age <= FEED_CACHE_FRESH_MS ? "fresh" : "stale" };
  } catch {
    localStorage.removeItem(STORAGE_KEY);
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
  localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
}
