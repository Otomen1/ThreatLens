import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ACTIVITY_KINDS, FEED_VISIT_KEY, FEED_VISIT_SESSION_KEY, FEED_VISIT_SESSION_MS, finishFeedVisit, isFeedActivity, startFeedVisit } from "./feedVisit";

const now = Date.parse("2026-10-17T06:00:00Z");
const earlier = new Date(now - 86400000).toISOString(), checked = new Date(now).toISOString();
const storage = () => { const values = new Map<string, string>(); return { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) }; };
beforeEach(() => { vi.stubGlobal("localStorage", storage()); vi.stubGlobal("sessionStorage", storage()); });
afterEach(() => vi.unstubAllGlobals());

describe("public feed visit continuity", () => {
  it("starts without invented history and writes only after a successful check", () => {
    const visit = startFeedVisit(now);
    expect(visit.baseline).toBeNull(); expect(localStorage.getItem(FEED_VISIT_KEY)).toBeNull();
    const result = finishFeedVisit(visit, checked, false, now);
    expect(result.persisted).toBe(true);
    expect(result.visit.baseline).toBe(checked);
    expect(JSON.parse(localStorage.getItem(FEED_VISIT_KEY)!)).toEqual({ version: 1, checked_at: checked });
    expect(Object.keys(JSON.parse(sessionStorage.getItem(FEED_VISIT_SESSION_KEY)!))).toEqual(["version", "baseline", "opened_at"]);
  });
  it("keeps the previous-visit baseline through reloads, filters, and successful checks", () => {
    localStorage.setItem(FEED_VISIT_KEY, JSON.stringify({ version: 1, checked_at: earlier }));
    const visit = startFeedVisit(now);
    expect(visit.baseline).toBe(earlier);
    finishFeedVisit(visit, checked, false, now);
    expect(startFeedVisit(now + 1000).baseline).toBe(earlier);
    expect(startFeedVisit(now + FEED_VISIT_SESSION_MS).baseline).toBe(checked);
  });
  it("does not move the last successful visit backwards across tabs", () => {
    const visit = startFeedVisit(now);
    finishFeedVisit(visit, checked, false, now);
    finishFeedVisit({ ...visit, baseline: earlier }, earlier, false, now);
    expect(JSON.parse(localStorage.getItem(FEED_VISIT_KEY)!).checked_at).toBe(checked);
  });
  it("caught-up changes only the visit baseline, never bookmarks or reading state", () => {
    localStorage.setItem(FEED_VISIT_KEY, JSON.stringify({ version: 1, checked_at: earlier }));
    localStorage.setItem("threatlens.feed.saved.v1", "keep bookmarks");
    localStorage.setItem("threatlens.feed.read.v1", "keep read state");
    finishFeedVisit(startFeedVisit(now), checked, true, now);
    expect(startFeedVisit(now).baseline).toBe(checked);
    expect(localStorage.getItem("threatlens.feed.saved.v1")).toBe("keep bookmarks");
    expect(localStorage.getItem("threatlens.feed.read.v1")).toBe("keep read state");
  });
  it("rejects malformed, future, oversized, unsupported and expired session records", () => {
    for (const bad of ["bad", "null", "x".repeat(513), JSON.stringify({ version: 2, checked_at: earlier }), JSON.stringify({ version: 1, checked_at: "2026-10-19T00:00:00Z" })]) {
      localStorage.setItem(FEED_VISIT_KEY, bad); sessionStorage.removeItem(FEED_VISIT_SESSION_KEY);
      expect(startFeedVisit(now).baseline).toBeNull();
    }
    sessionStorage.setItem(FEED_VISIT_SESSION_KEY, JSON.stringify({ version: 1, baseline: earlier, opened_at: now + 1 }));
    expect(startFeedVisit(now).baseline).toBeNull();
    expect(() => finishFeedVisit({ baseline: null, opened_at: now }, "bad", false, now)).toThrow();
  });
  it("retains the in-memory baseline and reports blocked browser storage", () => {
    const blocked = { getItem: () => { throw new Error(); }, setItem: () => { throw new Error(); } };
    vi.stubGlobal("localStorage", blocked); vi.stubGlobal("sessionStorage", blocked);
    const visit = startFeedVisit(now);
    expect(visit.baseline).toBeNull();
    expect(finishFeedVisit(visit, checked, false, now)).toEqual({ persisted: false, visit: { baseline: checked, opened_at: now } });
  });
});

it("accepts bounded compact activity only and rejects unsafe links, impossible dates and malformed groups", () => {
  const valid = { since: earlier, window_start: earlier, generated_at: checked, limited: false, groups: Object.fromEntries(ACTIVITY_KINDS.map((kind) => [kind, { total: 0, items: [] }])) };
  expect(isFeedActivity(valid, now)).toBe(true);
  const record = { ...valid, groups: { ...valid.groups, news: { total: 1, items: [{ id: "example", kind: "news", title: "Example", source: "Test", activity_at: checked, href: "/threat-feed/example" }] } } };
  expect(isFeedActivity(record, now)).toBe(true);
  for (const update of [{ href: "javascript:alert(1)" }, { kind: "poc" }, { id: "bad/path" }, { activity_at: "2026-10-18T00:00:00Z" }, { activity_at: earlier }]) {
    expect(isFeedActivity({ ...record, groups: { ...record.groups, news: { total: 1, items: [{ ...record.groups.news.items[0], ...update }] } } }, now)).toBe(false);
  }
  expect(isFeedActivity({ ...record, groups: { news: { total: 4, items: Array(4).fill(record.groups.news.items[0]) } } }, now)).toBe(false);
  expect(isFeedActivity({ ...valid, generated_at: "invalid" }, now)).toBe(false);
  expect(isFeedActivity({}, now)).toBe(false);
});
