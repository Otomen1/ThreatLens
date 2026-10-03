import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearFeedBookmarks, savedFeed, saveFeedBookmark } from "./feedBookmarks";

describe("feed bookmarks", () => {
  beforeEach(() => {
    const items = new Map<string, string>();
    vi.stubGlobal("localStorage", { getItem: (key: string) => items.get(key) ?? null,
      setItem: (key: string, value: string) => items.set(key, value) });
    vi.stubGlobal("window", { dispatchEvent: vi.fn() });
  });
  afterEach(() => vi.unstubAllGlobals());
  it("migrates older IDs without storing article content", () => {
    localStorage.setItem("threatlens.feed.bookmarks", JSON.stringify(["news-1"]));
    localStorage.setItem("threatlens.feed.iocs.bookmarks", JSON.stringify(["ioc-1"]));
    expect(savedFeed().map((r) => r.kind)).toEqual(["news", "ioc"]);
    expect(savedFeed()[1].href).toBe("/threat-feed/ioc-reports/ioc-1");
  });
  it("toggles and clears without remigrating deleted records", () => {
    expect(saveFeedBookmark("vulnerability", "CVE-2026-1234", "Example")).toBe(true);
    expect(savedFeed()).toHaveLength(1);
    expect(saveFeedBookmark("vulnerability", "CVE-2026-1234", "Example")).toBe(false);
    localStorage.setItem("threatlens.feed.bookmarks", JSON.stringify(["old"]));
    clearFeedBookmarks(); expect(savedFeed()).toEqual([]);
  });
  it("rejects malformed data and unsafe links", () => {
    localStorage.setItem("threatlens.feed.saved.v1", "bad json"); expect(savedFeed()).toEqual([]);
    localStorage.setItem("threatlens.feed.saved.v1", JSON.stringify({ version: 1, items: [{ kind: "news", id: "x", title: "test", href: "javascript:alert(1)", saved_at: new Date().toISOString() }] }));
    expect(savedFeed()).toEqual([]);
  });
  it("bounds entries at 500", () => {
    for (let i = 0; i < 505; i++) saveFeedBookmark("news", String(i), "Example");
    expect(savedFeed()).toHaveLength(500); expect(savedFeed()[0].id).toBe("5");
  });
});
