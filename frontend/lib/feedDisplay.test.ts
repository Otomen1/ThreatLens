import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FEED_DISPLAY_KEY, readFeedDisplay, writeFeedDisplay, markFeedRead, readFeedReading, relativeAge, exactDate } from "./feedDisplay";

describe("feed display and reading", () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    vi.stubGlobal("localStorage", { getItem: (k: string) => values.get(k) ?? null, setItem: (k: string, v: string) => values.set(k, v) });
    vi.stubGlobal("window", { dispatchEvent: vi.fn() });
  });
  afterEach(() => vi.unstubAllGlobals());
  it("validates presentation only and survives malformed or unavailable storage", () => {
    localStorage.setItem(FEED_DISPLAY_KEY, JSON.stringify({ version: 1, value: { density: "comfortable", hidden: { news: ["source", "token", "toString", "source"], poc: ["query"] }, query: "private" } }));
    expect(readFeedDisplay()).toEqual({ density: "comfortable", hidden: { news: ["source"] } });
    localStorage.setItem(FEED_DISPLAY_KEY, "bad"); expect(readFeedDisplay().density).toBe("compact");
    vi.stubGlobal("localStorage", { getItem: () => { throw new Error(); }, setItem: () => { throw new Error(); } });
    expect(readFeedDisplay().hidden).toEqual({}); expect(writeFeedDisplay({ density: "compact", hidden: {} })).toBe(false);
  });
  it("migrates reading state and namespaces same IDs", () => {
    localStorage.setItem("threatlens.feed.viewed", JSON.stringify(["old", 123]));
    localStorage.setItem("threatlens.feed.vulnerabilities.viewed", JSON.stringify(["CVE-2026-1234"]));
    markFeedRead("ioc", "old");
    expect([...readFeedReading()]).toEqual(["news:old", "vulnerability:CVE-2026-1234", "ioc:old"]);
  });
  it("bounds each reading kind and ignores unsafe IDs", () => {
    for (let i = 0; i < 505; i++) markFeedRead("news", String(i));
    markFeedRead("news", "bad/id");
    expect(readFeedReading().size).toBe(500); expect(readFeedReading().has("news:0")).toBe(false);
  });
  it("formats honest live ages and exact offsets", () => {
    const now = Date.parse("2026-10-06T00:00:00Z");
    expect(relativeAge("2026-10-05T22:00:00Z", now)).toBe("2h ago");
    expect(relativeAge("2026-10-07T00:00:00Z", now)).toBe("Scheduled / future date");
    expect(relativeAge("invalid", now)).toBe("Not supplied");
    expect(exactDate("2026-10-05T22:00:00Z")).toMatch(/GMT/);
  });
});
