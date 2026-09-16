import { beforeEach, describe, expect, it, vi } from "vitest";
import { readFeedHomeCache, writeFeedHomeCache } from "./threatFeedCache";
import type { FeedHomeParams, FeedHomeResponse } from "./api/threatFeed";

const values = new Map<string, string>();
const params: FeedHomeParams = { query: "", topic: "", hours: 168, limit_per_region: 5 };
const response = {
  summary: { regions: { global: { total: 0, recent: 0 }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, critical: 0, new_iocs: 0, last_refreshed_at: null, next_refresh_at: null, source_errors: 0 },
  sections: { global: { items: [], total: 0 }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } },
  generated_at: "2026-09-16T00:00:00Z",
} satisfies FeedHomeResponse;

beforeEach(() => {
  values.clear();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  });
});

describe("Threat Feed browser cache", () => {
  it("returns a matching fresh response", () => {
    writeFeedHomeCache(params, response);
    expect(readFeedHomeCache(params)).toEqual({ response, freshness: "fresh" });
  });

  it("does not reuse a response for different filters", () => {
    writeFeedHomeCache(params, response);
    expect(readFeedHomeCache({ ...params, topic: "malware" })).toBeNull();
  });

  it("removes malformed cached data", () => {
    localStorage.setItem("threatlens.feed.home.v1", "not-json");
    expect(readFeedHomeCache(params)).toBeNull();
  });
});
