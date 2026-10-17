import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { captureFeedPreset, FEED_PRESETS_KEY, feedPresetHref, readFeedPresets, removeFeedPreset, saveFeedPreset } from "./feedPresets";

describe("browser-local feed presets", () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    vi.stubGlobal("localStorage", { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value) });
    vi.stubGlobal("window", { dispatchEvent: vi.fn() });
  });
  afterEach(() => vi.unstubAllGlobals());
  it("captures only safe filters, not searches, pages, credentials or URLs", () => {
    const draft = captureFeedPreset("news", new URLSearchParams("source=ahnlab&topic=malware&hours=24&sort=oldest&query=private@example.test&page=3&token=secret&href=https://evil.test"), "malaysia");
    expect(draft).toEqual({ view: "news", region: "malaysia", filters: { hours: "24", sort: "oldest", topic: "malware", source: "ahnlab" } });
    saveFeedPreset("Malaysia research", draft);
    expect(localStorage.getItem(FEED_PRESETS_KEY)).not.toMatch(/private@|secret|evil|query|page/);
    expect(feedPresetHref(draft)).toBe("/threat-feed/news/malaysia?topic=malware&source=ahnlab&hours=24&sort=oldest");
  });
  it("supports all stored feed views and excludes homepage oldest sorting", () => {
    expect(captureFeedPreset("news", new URLSearchParams("sort=oldest&source=bad/host&hours=2")).filters).toEqual({ hours: "168" });
    expect(feedPresetHref(captureFeedPreset("vulnerabilities", new URLSearchParams("category=zero_days&severity=critical&source=NVD&sort=oldest")))).toContain("tab=vulnerabilities&hours=168&sort=oldest&category=zero_days&severity=critical&source=NVD");
    expect(feedPresetHref(captureFeedPreset("iocs", new URLSearchParams("vendor=talos&kind=domain&view=indicators&query=private.test")))).toBe("/threat-feed?tab=iocs&hours=168&vendor=talos&kind=domain&view=indicators");
  });
  it("round trips, rejects duplicate names and removes only its own record", () => {
    localStorage.setItem("threatlens.feed.saved.v1", "keep");
    const first = saveFeedPreset("Recent", captureFeedPreset("news", new URLSearchParams()));
    expect(() => saveFeedPreset(" RECENT ", first)).toThrow(/already exists/);
    saveFeedPreset("Critical", captureFeedPreset("vulnerabilities", new URLSearchParams("severity=critical")));
    expect(readFeedPresets()).toHaveLength(2);
    removeFeedPreset(first.id);
    expect(readFeedPresets().map((item) => item.name)).toEqual(["Critical"]);
    expect(localStorage.getItem("threatlens.feed.saved.v1")).toBe("keep");
  });
  it("bounds records without evicting existing presets", () => {
    for (let i = 0; i < 10; i++) saveFeedPreset(`Preset ${i}`, captureFeedPreset("news", new URLSearchParams()));
    expect(() => saveFeedPreset("Overflow", captureFeedPreset("news", new URLSearchParams()))).toThrow(/10-preset/);
    expect(readFeedPresets()[0].name).toBe("Preset 0");
  });
  it("recovers from corrupt/unsupported records and strips untrusted fields", () => {
    const good = saveFeedPreset("Valid", captureFeedPreset("news", new URLSearchParams()));
    for (const bad of ["bad", "null", JSON.stringify({ version: 2, items: [good] }), "x".repeat(32769)]) {
      localStorage.setItem(FEED_PRESETS_KEY, bad); expect(readFeedPresets()).toEqual([]);
    }
    localStorage.setItem(FEED_PRESETS_KEY, JSON.stringify({ version: 1, items: [
      { ...good, filters: { query: "secret", href: "javascript:alert(1)" }, href: "https://evil.test" },
      { ...good, id: "bad", view: "poc" }, { ...good, id: "bad2", saved_at: "invalid" },
      { ...good, id: "bad3", region: "unknown" }, { ...good, id: "bad4", filters: [] }, good,
    ] }));
    expect(readFeedPresets()).toEqual([{ ...good, filters: { hours: "168" } }]);
    expect(feedPresetHref(readFeedPresets()[0])).toBe("/threat-feed?hours=168");
  });
  it("reports blocked storage rather than claiming a preset was saved", () => {
    vi.stubGlobal("localStorage", { getItem: () => { throw new Error(); }, setItem: () => { throw new Error(); } });
    expect(readFeedPresets()).toEqual([]);
    expect(() => saveFeedPreset("Blocked", captureFeedPreset("news", new URLSearchParams()))).toThrow(/unavailable/);
  });
});
