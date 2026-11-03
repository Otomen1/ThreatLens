import type { FeedHomeParams, FeedHomeResponse } from "./api/threatFeed";
import { isNewsItem, validSourceOptions } from "./newsFeed";
import { readPublicFeedCache, writePublicFeedCache } from "./publicFeedCache";
export { FEED_CACHE_FRESH_MS, FEED_CACHE_MAX_MS } from "./publicFeedCache";
const KEY = "threatlens.feed.home.v1";
export function feedHomeCacheKey(params: FeedHomeParams): string {
  return JSON.stringify({ query: (params.query ?? "").trim().toLowerCase(), topic: params.topic ?? "", hours: params.hours ?? null, limit_per_region: params.limit_per_region ?? 5, sort: params.sort ?? "newest", ...(params.source ? { source: params.source } : {}) });
}
export function isFeedHomeResponse(value: unknown): value is FeedHomeResponse {
  if (!value || typeof value !== "object") return false;
  const data = value as FeedHomeResponse;
  return typeof data.generated_at === "string" && !!data.summary?.regions && !!data.sections && validSourceOptions(data.source_options)
    && ["global", "malaysia", "southeast_asia"].every((region) => {
      const key = region as keyof FeedHomeResponse["sections"];
      const section = data.sections[key], counts = data.summary.regions[key];
      return counts && [counts.total, counts.recent, section?.total].every((n) => Number.isInteger(n) && n >= 0)
        && Array.isArray(section.items) && section.items.length <= 20 && section.items.every(isNewsItem);
    }) && [data.summary.new_iocs, data.summary.critical, data.summary.source_errors].every((n) => Number.isInteger(n) && n >= 0);
}
export const readFeedHomeCache = (params: FeedHomeParams) => readPublicFeedCache(KEY, feedHomeCacheKey(params), isFeedHomeResponse);
export const writeFeedHomeCache = (params: FeedHomeParams, response: FeedHomeResponse) => writePublicFeedCache(KEY, feedHomeCacheKey(params), response, isFeedHomeResponse);
