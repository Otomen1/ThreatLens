import type { FeedList } from "./api/threatFeed";
import { isNewsItem, validSourceOptions } from "./newsFeed";
import { clearPublicFeedCache, readPublicFeedCache, writePublicFeedCache } from "./publicFeedCache";
const KEY = "threatlens.feed.news-regions.v1";
export function isNewsListing(value: unknown): value is FeedList {
  if (!value || typeof value !== "object") return false;
  const response = value as FeedList;
  return Number.isInteger(response.total) && response.total >= 0 && Number.isInteger(response.page) && response.page > 0
    && response.page_size === 10 && Array.isArray(response.items) && response.items.length <= 10
    && response.items.every(isNewsItem) && validSourceOptions(response.source_options);
}
export const readNewsRegionCache = (key: string) => readPublicFeedCache(KEY, key, isNewsListing);
export const writeNewsRegionCache = (key: string, response: FeedList) => writePublicFeedCache(KEY, key, response, isNewsListing);
export const clearNewsRegionCache = () => clearPublicFeedCache(KEY);
