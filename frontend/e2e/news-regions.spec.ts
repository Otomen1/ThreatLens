import { expect, test, type Page } from "@playwright/test";

const labels = { global: "Global", southeast_asia: "Southeast Asia", malaysia: "Malaysia" };
const slugs = { global: "global", southeast_asia: "southeast-asia", malaysia: "malaysia" };
type Region = keyof typeof labels;
const now = Date.now();
const news = (region: Region, index: number) => ({
  id: `${region}-${index}`, source_id: "ahnlab", source_name: "AhnLab ASEC", source_kind: "rss",
  title: `${labels[region]} report ${index + 1}`, excerpt: "Publisher metadata", summary: "Synthetic source-reported news.",
  url: `https://example.test/${region}/${index}`, published_at: new Date(now - (region === "global" ? 0 : 86400000) - index * 60000).toISOString(),
  region, relevance: "general", region_reasons: ["Synthetic regional signal"], topic: "research", severity: null, entities: [],
});
const rows = { global: Array.from({ length: 24 }, (_, i) => news("global", i)), southeast_asia: Array.from({ length: 12 }, (_, i) => news("southeast_asia", i)), malaysia: Array.from({ length: 3 }, (_, i) => news("malaysia", i)) };
async function mocks(page: Page) {
  const requests: URL[] = [], errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.route("**/api/v1/**", route => {
    const url = new URL(route.request().url()); requests.push(url);
    const path = url.pathname;
    if (path.endsWith("/threat-feed/home")) return route.fulfill({ json: {
      generated_at: new Date(now).toISOString(), summary: { regions: { global: { total: 24, recent: 24 }, southeast_asia: { total: 12, recent: 0 }, malaysia: { total: 3, recent: 0 } }, new_iocs: 5, critical: 0, source_errors: 0, last_refreshed_at: new Date(now).toISOString() },
      sections: Object.fromEntries(Object.entries(rows).map(([region, values]) => [region, { items: values.slice(0, Number(url.searchParams.get("limit_per_region") ?? 5)), total: values.length }])),
    } });
    if (path.endsWith("/threat-feed/items")) {
      const region = url.searchParams.get("region") as Region; const page = Number(url.searchParams.get("page") ?? 1);
      const filtered = url.searchParams.get("topic") === "malware" ? [] : rows[region] ?? [];
      const sorted = url.searchParams.get("sort") === "oldest" ? filtered.toReversed() : filtered;
      return route.fulfill({ json: { items: sorted.slice((page - 1) * 10, page * 10), total: sorted.length, page, page_size: 10 } });
    }
    if (path.includes("/threat-feed/items/")) {
      const found = Object.values(rows).flat().find(row => row.id === path.split("/").at(-1));
      return route.fulfill({ json: found });
    }
    if (path.endsWith("/threat-feed/refresh")) return route.fulfill({ json: { status: "cooldown", items_added: 0, next_refresh_at: new Date(now + 60000).toISOString() } });
    if (path.endsWith("/threat-feed/status")) return route.fulfill({ json: { sources: [], generated_at: new Date(now).toISOString(), next_refresh_at: null } });
    if (path.includes("/related/")) return route.fulfill({ json: { items: [], cves: [] } });
    return route.fulfill({ json: { status: "ok" } });
  });
  return { requests, errors };
}

test("homepage shows the latest ten across regions and three regional cards", async ({ page }) => {
  const { requests, errors } = await mocks(page); await page.goto("/threat-feed");
  const table = page.getByRole("table", { name: "Latest 10 news" });
  await expect(table.getByRole("row")).toHaveCount(11);
  await expect(table.getByRole("link", { name: "Global report 10", exact: true })).toBeVisible();
  await expect(table.getByRole("link", { name: "Global report 11", exact: true })).toHaveCount(0);
  await expect(page.getByText("New in 24 hours", { exact: true })).toBeVisible();
  await expect(page.getByText("Last refresh", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => ["global", "malaysia", "southeast_asia"].map(region => localStorage.getItem(`threatlens.feed.seen.${region}`)))).toEqual([null, null, null]);
  const cards = page.getByRole("region", { name: "Browse by region" });
  await expect(cards.getByRole("heading", { level: 3 })).toHaveText([/Global$/, /Southeast Asia$/, /Malaysia$/]);
  expect(requests.filter(url => url.pathname.endsWith("/home"))).toHaveLength(1);
  expect(requests.find(url => url.pathname.endsWith("/home"))?.searchParams.get("limit_per_region")).toBe("10");
  expect(requests.some(url => /investigate|poc\/lookup|threat-feed\/refresh/.test(url.pathname))).toBe(false);
  expect(errors).toEqual([]);
  if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: "test-results/news-home-desktop.png", fullPage: true });
});

test("regional cards open public ten-row pages without an extra homepage request", async ({ page }) => {
  const { requests, errors } = await mocks(page); await page.goto("/threat-feed");
  const cards = page.getByRole("region", { name: "Browse by region" });
  await cards.getByRole("link", { name: /Global/ }).click();
  await expect(page).toHaveURL(/\/news\/global$/);
  await expect(page.getByRole("table", { name: "Global reports" }).getByRole("row")).toHaveCount(11);
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page).toHaveURL(/page=2/); await expect(page.getByRole("link", { name: "Global report 11", exact: true })).toBeVisible();
  await expect(page.getByText("Page 2 of 3", { exact: true })).toBeVisible();
  expect(requests.filter(url => url.pathname.endsWith("/home"))).toHaveLength(1);
  expect(requests.filter(url => url.pathname.endsWith("/items")).every(url => url.searchParams.get("page_size") === "10")).toBe(true);
  await page.getByRole("link", { name: "← Back to News", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Latest 10 news", exact: true })).toBeVisible();
  await page.getByRole("region", { name: "Browse by region" }).getByRole("link", { name: /Malaysia/ }).click();
  await expect(page.getByRole("table", { name: "Malaysia reports" }).getByRole("row")).toHaveCount(4);
  await expect(page.getByRole("button", { name: "Next", exact: true })).toBeDisabled();
  expect(errors).toEqual([]);
});

test("legacy URLs, filter reset and bookmarks preserve the regional workflow", async ({ page }) => {
  const { errors } = await mocks(page);
  await page.goto("/threat-feed?tab=news&region=global&page=2&hours=720&query=report");
  await expect(page).toHaveURL(/\/news\/global\?query=report&hours=720&page=2/);
  const table = page.getByRole("table", { name: "Global reports" });
  const target = table.getByRole("link", { name: "Global report 19", exact: true });
  await target.scrollIntoViewIfNeeded();
  const row = target.locator("xpath=ancestor::li"); const offset = (await row.boundingBox())!.y; const original = page.url();
  await target.click(); await expect(page.getByRole("heading", { name: "Global report 19", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save locally", exact: true }).click();
  expect(await page.evaluate(() => localStorage.getItem("threatlens.feed.saved.v1"))).toContain("global-18");
  await page.getByRole("link", { name: "← Back to Threat Feed", exact: true }).click();
  await expect(page).toHaveURL(original);
  await expect.poll(async () => Math.abs(((await row.boundingBox())?.y ?? -1000) - offset)).toBeLessThan(3);
  await page.getByRole("combobox", { name: "Topic", exact: true }).selectOption("malware");
  await expect.poll(() => new URL(page.url()).searchParams.get("topic")).toBe("malware");
  expect(new URL(page.url()).pathname).toBe("/threat-feed/news/global"); expect(new URL(page.url()).searchParams.has("page")).toBe(false);
  await expect(page.getByText("No matching reports yet.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Reset filters", exact: true }).click();
  expect(new URL(page.url()).pathname).toBe("/threat-feed/news/global");
  await expect(page.getByRole("link", { name: "Global report 1", exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("regional cache survives a failed background load and keeps cooldown feedback", async ({ page }) => {
  await mocks(page); await page.goto("/threat-feed/news/southeast-asia");
  await expect(page.getByRole("link", { name: "Southeast Asia report 1", exact: true })).toBeVisible();
  await page.route("**/api/v1/threat-feed/items?*", route => route.abort()); await page.reload();
  await expect(page.getByRole("link", { name: "Southeast Asia report 1", exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /last available reports/ })).toBeVisible();
  await page.getByRole("button", { name: "Refresh feed", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: /Refresh is cooling down/ })).toBeVisible();
});

test("obsolete regional responses cannot replace newer filters", async ({ page }) => {
  await mocks(page); let finish!: () => void; const pending = new Promise<void>(resolve => { finish = resolve; });
  await page.route("**/api/v1/threat-feed/items?*", async route => {
    const query = new URL(route.request().url()).searchParams.get("query");
    if (query === "slow") await pending;
    const item = { ...news("global", 0), title: query === "slow" ? "Obsolete report" : "Fresh report" };
    await route.fulfill({ json: { items: [item], total: 1, page: 1, page_size: 10 } }).catch(() => undefined);
  });
  await page.goto("/threat-feed/news/global"); await expect(page.getByRole("link", { name: "Fresh report", exact: true })).toBeVisible();
  const started = page.waitForRequest(request => request.url().includes("/threat-feed/items?") && new URL(request.url()).searchParams.get("query") === "slow");
  await page.getByRole("textbox", { name: "Search threat feed", exact: true }).fill("slow"); await started;
  await page.getByRole("textbox", { name: "Search threat feed", exact: true }).fill("fresh");
  await expect(page).toHaveURL(/query=fresh/); finish();
  await expect(page.getByRole("link", { name: "Fresh report", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Obsolete report", exact: true })).toHaveCount(0);
});

test("regional pages remain accessible on mobile and reject unknown regions", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 }); const { errors } = await mocks(page);
  await page.goto(`/threat-feed/news/${slugs.malaysia}`);
  await expect(page.getByRole("heading", { name: "Malaysia news", exact: true })).toBeVisible();
  await expect(page.getByRole("table", { name: "Malaysia reports" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: "test-results/news-malaysia-mobile.png", fullPage: true });
  await page.getByRole("link", { name: "Malaysia report 1", exact: true }).focus(); await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Malaysia report 1", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.goto("/threat-feed/news/unknown"); await expect(page.getByRole("heading", { name: "404", exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});
