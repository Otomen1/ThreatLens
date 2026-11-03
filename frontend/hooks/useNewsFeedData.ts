"use client";

import { useMemo } from "react";
import { getFeedHome, getFeedItems, type FeedHomeResponse, type FeedList, type FeedRegion } from "@/lib/api/threatFeed";
import { isFeedHomeResponse, readFeedHomeCache, writeFeedHomeCache } from "@/lib/threatFeedCache";
import { isNewsListing, readNewsRegionCache, writeNewsRegionCache } from "@/lib/newsRegionCache";
import { useCachedFeedData } from "./useCachedFeedData";
type Data = FeedHomeResponse | FeedList;
export function useNewsFeedData(region: FeedRegion | undefined, query: string, topic: string, hours: number, page: number, sort: string, source = "") {
  const options = useMemo(() => {
    const scope = region ?? "home";
    const key = JSON.stringify({ scope, query: query.trim().toLowerCase(), topic, hours, page: region ? page : 1, sort: region ? sort : "newest", ...(source ? { source } : {}) });
    const params = { query, topic, hours, source: source || undefined, limit_per_region: 10, sort: "newest" };
    return {
      key, scope, search: query,
      read: () => region ? readNewsRegionCache(key) : readFeedHomeCache(params),
      fetch: (fresh: boolean, signal: AbortSignal): Promise<Data> => region ? getFeedItems({ region, query, topic, hours, page, page_size: 10, sort, source: source || undefined }, { fresh, signal }) : getFeedHome(params, { fresh, signal }),
      valid: (value: unknown): value is Data => region ? isNewsListing(value) : isFeedHomeResponse(value),
      write: (value: Data) => { if ("sections" in value) writeFeedHomeCache(params, value); else writeNewsRegionCache(key, value); },
    };
  }, [region, query, topic, hours, page, sort, source]);
  const { data, ...state } = useCachedFeedData<Data>(options);
  return { ...state, home: data && "sections" in data ? data : null, listing: data && "items" in data ? data : null };
}
