import { expect, test, type Page } from "@playwright/test";

const now = new Date().toISOString();
const source_options = [{ id: "ahnlab", name: "AhnLab ASEC" }, { id: "eset", name: "ESET WeLiveSecurity" }];
const news = Array.from({ length: 24 }, (_, i) => ({
  id: `news-${i}`, title: `Synthetic news ${i + 1}`, source_id: i % 2 ? "eset" : "ahnlab", source_name: i % 2 ? "ESET WeLiveSecurity" : "AhnLab ASEC",
  published_at: new Date(Date.now() - i * 60000).toISOString(), region: "global", topic: "research", severity: null,
  excerpt: "Stored metadata", summary: "Test metadata", entities: [], url: `https://example.test/news/${i}`, source_kind: "rss", relevance: "general", region_reasons: [],
}));
const vulnerability = { id: "CVE-2026-1234", cve_id: "CVE-2026-1234", title: "Test vulnerability", description: "Stored metadata", published_at: now, activity_at: now, updated_at: now, products: [], severity: "critical", sources: ["NVD"], references: [], scores: [], reports: [], reported_zero_day: false, known_exploited: false };
const report = { id: "ioc-report", vendor: "talos", title: "Test IOC report", path: "example/iocs.txt", source_url: "https://example.test/report", article_url: null, published_at: now, activity_at: now, collected_at: now, commit: "a".repeat(40), blob: "b".repeat(40), parser_version: "1", license: "CC0-1.0", license_url: "https://example.test/license", attribution: "Cisco Talos", indicator_count: 1, types: ["domain"], warnings: [], withdrawn: false };

async function mocks(page: Page) {
  const requests: URL[] = [], errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url()); requests.push(url);
    const path = url.pathname;
    if (path.endsWith("/home") || path.endsWith("/items")) {
      const filtered = news.filter((item) => !url.searchParams.get("source") || item.source_id === url.searchParams.get("source"));
      const page = Number(url.searchParams.get("page") ?? 1);
      if (path.endsWith("/items")) return route.fulfill({ json: { source_options, items: filtered.slice((page - 1) * 10, page * 10), total: filtered.length, page, page_size: 10 } });
      return route.fulfill({ json: { source_options, generated_at: now, summary: { regions: { global: { total: news.length, recent: news.length }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, critical: 0, new_iocs: 0, source_errors: 0, last_refreshed_at: now }, sections: { global: { items: filtered.slice(0, 10), total: filtered.length }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } } } });
    }
    if (path.endsWith("/vulnerabilities")) return route.fulfill({ json: { items: [vulnerability], total: 1, page: 1, page_size: 20, sources: ["NVD"], published_24h: 1, zero_days_24h: 0, kev_added_24h: 0, sync_status: "current", last_synced_at: now, generated_at: now } });
    if (path.endsWith("/ioc-reports")) return route.fulfill({ json: { items: [report], total: 1, page: 1, page_size: 20, unique_indicators: 1, recent_indicators: 1, sources: [], generated_at: now } });
    if (path.endsWith("/status")) return route.fulfill({ json: { generated_at: now, sources: [], next_refresh_at: null } });
    return route.fulfill({ json: {} });
  });
  return { requests, errors };
}

test("publisher filtering survives regional navigation, pagination and reset", async ({ page }) => {
  const { requests, errors } = await mocks(page);
  await page.goto("/threat-feed");
  await page.getByLabel("News source", { exact: true }).selectOption("ahnlab");
  await expect(page).toHaveURL(/source=ahnlab/);
  await expect(page.getByRole("checkbox", { name: "Select current page" })).toBeEnabled();
  await expect(page.getByRole("table").getByRole("row")).toHaveCount(11);
  await expect(page.getByRole("table").getByText("ESET WeLiveSecurity")).toHaveCount(0);
  await page.getByRole("region", { name: "Browse by region" }).getByRole("link", { name: /Global/ }).click();
  await expect(page).toHaveURL(/\/news\/global\?source=ahnlab/);
  await expect(page.getByRole("checkbox", { name: "Select current page" })).toBeEnabled();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByRole("table").getByRole("row")).toHaveCount(3);
  expect(requests.filter((url) => url.pathname.endsWith("/items")).at(-1)?.searchParams.get("source")).toBe("ahnlab");
  await page.getByRole("button", { name: "Reset filters", exact: true }).click();
  await expect(page).not.toHaveURL(/source=|page=/);
  expect(errors).toEqual([]);
});

test("presets retain safe filters only, restore regional state and survive reload", async ({ page }) => {
  const { requests, errors } = await mocks(page);
  await page.goto("/threat-feed/news/global?source=ahnlab&hours=720&page=2&query=private@example.test");
  await page.getByText("Filter presets · Browser-local", { exact: true }).click();
  await page.getByRole("button", { name: "Save current filters", exact: true }).click();
  await page.getByLabel("Preset name", { exact: true }).fill("AhnLab 30 days");
  await page.getByRole("button", { name: "Save preset", exact: true }).click();
  const stored = await page.evaluate(() => localStorage.getItem("threatlens.feed.presets.v1"));
  expect(stored).not.toMatch(/private@|query|page=/);
  await page.goto("/threat-feed?tab=vulnerabilities&severity=critical");
  await page.getByText("Filter presets · Browser-local", { exact: true }).click();
  await page.getByRole("button", { name: "Save current filters", exact: true }).click();
  await page.getByLabel("Preset name", { exact: true }).fill("Critical vulnerabilities");
  await page.getByRole("button", { name: "Save preset", exact: true }).click();
  await page.reload();
  await page.getByText("Filter presets · Browser-local", { exact: true }).click();
  await page.getByLabel("Saved filter presets").selectOption({ label: "AhnLab 30 days · News" });
  await page.getByRole("button", { name: "Apply preset", exact: true }).click();
  await expect(page).toHaveURL(/\/news\/global\?source=ahnlab&hours=720$/);
  await expect(page.getByRole("heading", { name: "Global news", exact: true })).toBeVisible();
  await expect(page.getByLabel("News source", { exact: true })).toHaveValue("ahnlab");
  expect(requests.some((url) => /investigate|poc\/lookup|refresh/.test(url.pathname))).toBe(false);
  expect(errors).toEqual([]);
});

test("current-page bulk actions preserve duplicates and clear selection on navigation", async ({ page }) => {
  const { requests, errors } = await mocks(page);
  await page.addInitScript(() => localStorage.setItem("threatlens.feed.saved.v1", JSON.stringify({ version: 1, items: [{ kind: "news", id: "news-0", title: "Keep original bookmark", href: "/threat-feed/news-0", saved_at: new Date().toISOString() }] })));
  await page.goto("/threat-feed/news/global");
  const select = page.getByRole("checkbox", { name: "Select current page" });
  await expect(select).toBeEnabled();
  await select.check();
  await page.getByRole("button", { name: "Mark selected read", exact: true }).click();
  const toolbar = page.getByRole("region", { name: "Report selection" });
  await expect(toolbar.getByRole("status")).toHaveText("10 marked read · 0 already read.");
  await page.getByRole("button", { name: "Save selected", exact: true }).click();
  await expect(toolbar.getByRole("status")).toHaveText("9 saved · 1 already saved.");
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("threatlens.feed.saved.v1")!).items[0].title)).toBe("Keep original bookmark");
  await page.getByRole("button", { name: "Save selected", exact: true }).click();
  await expect(toolbar.getByRole("status")).toHaveText("0 saved · 10 already saved.");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByText("0 selected", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save selected", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Previous", exact: true }).click();
  await expect(page.getByText("0 selected", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("threatlens.feed.read.v1")!).ids.news.length)).toBe(10);
  expect(requests.some((url) => /investigate|poc\/lookup|refresh/.test(url.pathname))).toBe(false);
  expect(errors).toEqual([]);
});

test("vulnerability and IOC bulk controls work on mobile and surface storage errors", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const { requests, errors } = await mocks(page);
  await page.goto("/threat-feed?tab=vulnerabilities");
  const checkbox = page.getByRole("checkbox", { name: `Select ${vulnerability.title}`, exact: true });
  await expect(checkbox).toBeEnabled(); await checkbox.focus(); await page.keyboard.press("Space");
  await page.getByRole("button", { name: "Save selected", exact: true }).click();
  await expect(page.getByRole("region", { name: "Report selection" }).getByRole("status")).toHaveText("1 saved · 0 already saved.");
  await page.goto("/threat-feed?tab=iocs");
  await expect(page.getByRole("checkbox", { name: "Select current page" })).toBeEnabled();
  await page.getByRole("checkbox", { name: `Select ${report.title}`, exact: true }).check();
  await page.getByRole("button", { name: "Mark selected read", exact: true }).click();
  const toolbar = page.getByRole("region", { name: "Report selection" });
  await expect(toolbar.getByRole("status")).toHaveText("1 marked read · 0 already read.");
  await page.evaluate(() => { const original = Storage.prototype.setItem; Storage.prototype.setItem = function (key, value) { if (key === "threatlens.feed.saved.v1") throw new Error("Blocked"); return original.call(this, key, value); }; });
  await page.getByRole("button", { name: "Save selected", exact: true }).click();
  await expect(toolbar.getByRole("status")).toHaveText(/Could not save selected bookmarks/);
  await expect(page.getByRole("link", { name: report.title, exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(requests.some((url) => /investigate|poc\/lookup|refresh/.test(url.pathname))).toBe(false);
  expect(errors).toEqual([]);
});
