import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { addFeedBookmarks, clearFeedBookmarks, savedFeed, saveFeedBookmark, exportFeedBookmarks, parseBookmarkImport, mergeFeedBookmarks, previewBookmarkMerge } from "./feedBookmarks";

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
  it("exports metadata only and safely merges duplicates without replacing local records", () => {
    saveFeedBookmark("news", "one", "Local title");
    const bundle = exportFeedBookmarks();
    bundle.items[0].title = "Imported title";
    bundle.items.push({ ...bundle.items[0], id: "two", href: "/threat-feed/two" });
    const input = parseBookmarkImport(JSON.stringify(bundle));
    expect(previewBookmarkMerge(input).duplicates).toBe(1);
    expect(mergeFeedBookmarks(input)).toEqual({ added: 1, duplicates: 1, skipped: 0 });
    expect(savedFeed()[0].title).toBe("Local title");
    expect(mergeFeedBookmarks(input).added).toBe(0);
    expect(Object.keys(exportFeedBookmarks().items[0])).toEqual(["kind", "id", "title", "href", "saved_at"]);
  });
  it("rejects unsupported, malformed, oversized, unsafe-link and over-cap imports atomically", () => {
    saveFeedBookmark("news", "one", "Existing");
    const bundle = exportFeedBookmarks();
    for (const input of ["broken", JSON.stringify({ ...bundle, version: 2 }), JSON.stringify({ ...bundle, items: [{ ...bundle.items[0], href: "https://evil.test" }] }), JSON.stringify({ ...bundle, items: Array(501).fill(bundle.items[0]) }), "x".repeat(1_048_577)]) {
      expect(() => parseBookmarkImport(input)).toThrow(); expect(savedFeed()).toHaveLength(1);
    }
  });
  it("keeps existing entries at capacity and surfaces storage failure", () => {
    for (let i = 0; i < 500; i++) saveFeedBookmark("news", String(i), "Existing");
    const incoming = [{ kind: "news" as const, id: "new", title: "New", href: "/threat-feed/new", saved_at: new Date().toISOString() }];
    expect(mergeFeedBookmarks(incoming)).toEqual({ added: 0, duplicates: 0, skipped: 1 });
    expect(savedFeed()[0].id).toBe("0");
    vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => { throw new Error("quota"); } });
    expect(() => mergeFeedBookmarks(incoming)).toThrow();
  });
  it("bulk save adds only, preserves duplicate titles, and writes once", () => {
    saveFeedBookmark("news", "old", "Keep title");
    const writes = vi.spyOn(localStorage, "setItem"); vi.mocked(window.dispatchEvent).mockClear();
    expect(addFeedBookmarks("news", [{ id: "old", title: "Changed" }, { id: "new", title: "New" }, { id: "new", title: "Duplicate" }])).toEqual({ added: 1, duplicates: 2, skipped: 0 });
    expect(writes).toHaveBeenCalledTimes(1); expect(window.dispatchEvent).toHaveBeenCalledTimes(1);
    expect(savedFeed().map((item) => item.title)).toEqual(["Keep title", "New"]);
    expect(addFeedBookmarks("news", [{ id: "old", title: "Changed" }]).duplicates).toBe(1);
    expect(savedFeed()).toHaveLength(2);
  });
  it("bulk save caps additions, rejects malformed IDs and leaves current entries intact", () => {
    for (let i = 0; i < 500; i++) saveFeedBookmark("news", String(i), "Existing");
    expect(addFeedBookmarks("ioc", [{ id: "new", title: "New" }])).toEqual({ added: 0, duplicates: 0, skipped: 1 });
    expect(() => addFeedBookmarks("news", [{ id: "bad/id", title: "Bad" }])).toThrow();
    expect(() => addFeedBookmarks("news", Array(101).fill({ id: "id", title: "Title" }))).toThrow();
    expect(savedFeed()[0].id).toBe("0");
  });
});
