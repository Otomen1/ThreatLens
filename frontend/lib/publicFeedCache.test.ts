import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { readPublicFeedCache, writePublicFeedCache } from "./publicFeedCache";

const values = new Map<string, string>();
const valid = (value: unknown): value is string => typeof value === "string";
beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2026-11-03T00:00:00Z")); values.clear();
  vi.stubGlobal("localStorage", { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

it("imports a legacy response without extending its freshness or retention", () => {
  values.set("legacy", JSON.stringify({ version: 1, key: "page", savedAt: Date.now() - 6 * 60000, response: "old" }));
  expect(readPublicFeedCache("legacy", "page", valid)).toEqual({ response: "old", freshness: "stale" });
  vi.advanceTimersByTime(24 * 3600000);
  expect(readPublicFeedCache("legacy", "page", valid)).toBeNull();
  expect(values.has("legacy")).toBe(false);
});

it("bounds entries and serialized bytes while retaining the newest pages", () => {
  for (let index = 0; index < 10; index++) writePublicFeedCache("small", String(index), "row", valid);
  expect(JSON.parse(values.get("small")!).entries).toHaveLength(8);
  expect(readPublicFeedCache("small", "0", valid)).toBeNull();
  for (let index = 0; index < 8; index++) writePublicFeedCache("large", String(index), "x".repeat(150000), valid);
  expect(values.get("large")!.length * 2).toBeLessThanOrEqual(1024 * 1024);
  expect(readPublicFeedCache("large", "7", valid)?.response).toHaveLength(150000);
});

it("does not replace good cached data with an invalid write", () => {
  writePublicFeedCache("feed", "filter", "good", valid);
  writePublicFeedCache<unknown>("feed", "filter", { bad: true }, valid);
  expect(readPublicFeedCache("feed", "filter", valid)?.response).toBe("good");
});
