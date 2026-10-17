import { describe, expect, it } from "vitest";
import { NEWS_REGIONS, latestNews, newsHref, newsPath, newsRegionFromSlug } from "./newsFeed";
import type { FeedHomeResponse, FeedItem, FeedRegion } from "./api/threatFeed";
import { isPrivateList, isRecoverableList, ListRecoveryStore } from "./listRecovery";

function item(id: string, region: FeedRegion, minute: number): FeedItem {
  return { id, region, published_at: new Date(Date.UTC(2026, 9, 15, 10, minute)).toISOString() } as FeedItem;
}
function home(items: FeedItem[]): FeedHomeResponse {
  return { sections: Object.fromEntries(NEWS_REGIONS.map((region) => [region, { items: items.filter((item) => item.region === region), total: 20 }])) } as FeedHomeResponse;
}
describe("News selection and navigation", () => {
  it("finds all ten newest reports even when they belong to one region", () => {
    const records = [...Array.from({ length: 10 }, (_, i) => item(`global-${i}`, "global", i + 10)), item("my", "malaysia", 1), item("sea", "southeast_asia", 2)];
    const newest = latestNews(home(records));
    expect(newest).toHaveLength(10); expect(newest.every((row) => row.region === "global")).toBe(true);
    expect(newest[0].id).toBe("global-9");
  });
  it("mixes regions by publication date, deduplicates IDs and uses stable ties", () => {
    const response = home([item("a", "global", 1), item("b", "malaysia", 1), item("new", "southeast_asia", 5)]);
    response.sections.global.items.push(item("new", "southeast_asia", 5));
    expect(latestNews(response).map((row) => row.id)).toEqual(["new", "b", "a"]);
    expect(latestNews(home([]))).toEqual([]);
  });
  it("keeps only supported filters and encodes regional routes", () => {
    const query = new URLSearchParams("region=southeast_asia&page=3&query=two+words&topic=malware&hours=24&sort=oldest&tab=news&token=ignored");
    expect(newsHref("southeast_asia", query, true)).toBe("/threat-feed/news/southeast-asia?query=two+words&topic=malware&hours=24&sort=oldest&page=3");
    expect(newsHref(undefined, query)).toBe("/threat-feed?query=two+words&topic=malware&hours=24");
    expect(newsHref("malaysia", query)).not.toContain("page=");
    expect(newsRegionFromSlug("southeast-asia")).toBe("southeast_asia");
    expect(newsRegionFromSlug("unknown")).toBeUndefined();
  });
  it("treats regional lists as public and recovers the article's true origin", () => {
    const store = new ListRecoveryStore();
    for (const region of NEWS_REGIONS) {
      const path = newsPath(region);
      expect(isRecoverableList(path)).toBe(true); expect(isPrivateList(path)).toBe(false);
      store.save({ id: region, url: `${path}?page=2`, private: false, y: 700, anchor: "/threat-feed/report", offset: 200, detail: "/threat-feed/report" });
    }
    store.clearPrivate();
    expect(store.origin("/threat-feed/report", "/threat-feed")?.url).toBe("/threat-feed/news/malaysia?page=2");
    expect(isRecoverableList("/threat-feed/news/unknown")).toBe(false);
  });
  it("preserves selected publisher in regional, legacy and back links", () => {
    const params = new URLSearchParams("source=ahnlab&hours=720&page=2&tab=news&region=malaysia");
    expect(newsHref("malaysia", params, true)).toBe("/threat-feed/news/malaysia?source=ahnlab&hours=720&page=2");
    expect(newsHref(undefined, params)).toBe("/threat-feed?source=ahnlab&hours=720");
  });
});
