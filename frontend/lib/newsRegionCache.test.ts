import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearNewsRegionCache, readNewsRegionCache, writeNewsRegionCache } from "./newsRegionCache";
import type { FeedList } from "./api/threatFeed";

const values = new Map<string, string>();
const KEY = "threatlens.feed.news-regions.v1";
const result: FeedList = { page: 1, page_size: 10, total: 1, items: [{ id: "news", title: "Test report", source_name: "Test publisher", published_at: "2026-10-15T00:00:00Z", region: "malaysia", topic: "research", severity: null } as FeedList["items"][number]] };
beforeEach(() => {
  values.clear(); vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-15T01:00:00Z"));
  vi.stubGlobal("localStorage", { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });
describe("Bounded regional News browser cache", () => {
  it("separates filters, retains at most three entries and replaces a matching key", () => {
    for (const key of ["my:1", "my:2", "sea:1", "global:1"]) writeNewsRegionCache(key, result);
    expect(readNewsRegionCache("my:1")).toBeNull(); expect(readNewsRegionCache("my:2")?.response).toEqual(result);
    writeNewsRegionCache("my:2", { ...result, total: 2 });
    expect(JSON.parse(values.get(KEY)!).entries).toHaveLength(3);
    expect(readNewsRegionCache("my:2")?.response.total).toBe(2);
    expect(readNewsRegionCache("different filters")).toBeNull();
  });
  it("is fresh for five minutes, provides a stale fallback and expires after 24 hours", () => {
    writeNewsRegionCache("my", result); expect(readNewsRegionCache("my")?.freshness).toBe("fresh");
    vi.advanceTimersByTime(6 * 60000); expect(readNewsRegionCache("my")?.freshness).toBe("stale");
    vi.advanceTimersByTime(24 * 3600000); expect(readNewsRegionCache("my")).toBeNull(); expect(values.has(KEY)).toBe(false);
  });
  it("drops malformed records and clears only its own cache", () => {
    values.set(KEY, "not-json"); expect(readNewsRegionCache("my")).toBeNull(); expect(values.has(KEY)).toBe(false);
    values.set(KEY, JSON.stringify({ version: 1, entries: [{ key: "my", savedAt: Date.now(), response: {} }] }));
    expect(readNewsRegionCache("my")).toBeNull();
    values.set("bookmarks", "keep"); writeNewsRegionCache("my", result); clearNewsRegionCache(); expect(values.get("bookmarks")).toBe("keep");
  });
  it("does not turn unavailable browser storage into a failed feed load", () => {
    vi.stubGlobal("localStorage", { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); }, removeItem() { throw new Error("blocked"); } });
    expect(readNewsRegionCache("my")).toBeNull(); expect(() => writeNewsRegionCache("my", result)).not.toThrow(); expect(() => clearNewsRegionCache()).not.toThrow();
  });
});
