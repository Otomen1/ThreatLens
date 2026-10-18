import { expect, test, type Page } from "@playwright/test";

const now = Date.now(), timestamp = new Date(now).toISOString();
const news = Array.from({ length: 10 }, (_, i) => ({ id: `layout-${i}`, title: `Readable report ${i + 1}`, source_id: "talos", source_name: "Cisco Talos", source_kind: "rss", excerpt: "Source metadata", summary: "Stored metadata", url: `https://example.test/${i}`, published_at: new Date(now - i * 60000).toISOString(), region: "global", relevance: "general", region_reasons: [], topic: "research", severity: i === 0 ? "high" : null, entities: [] }));
async function mocks(page: Page) {
  const requests: string[] = [], errors: string[] = [];
  await page.addInitScript((checked_at) => { if (!localStorage.getItem("threatlens.feed.visit.v1")) localStorage.setItem("threatlens.feed.visit.v1", JSON.stringify({ version: 1, checked_at })); }, new Date(now - 86400000).toISOString());
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname; requests.push(path);
    if (path.endsWith("/home")) return route.fulfill({ json: { generated_at: timestamp, source_options: [{ id: "talos", name: "Cisco Talos" }], summary: { regions: { global: { total: 10, recent: 10 }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, critical: 0, new_iocs: 0, source_errors: 0, last_refreshed_at: timestamp }, sections: { global: { items: news, total: 10 }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } } } });
    if (path.endsWith("/activity")) return route.fulfill({ json: { since: new Date(now - 86400000).toISOString(), window_start: new Date(now - 86400000).toISOString(), generated_at: timestamp, limited: false, groups: { news: { total: 10, items: [] }, vulnerability: { total: 2, items: [] }, ioc: { total: 1, items: [] } } } });
    if (path.endsWith("/ioc-reports")) return route.fulfill({ json: { items: Array.from({ length: 20 }, (_, i) => ({ id: `ioc-${i}`, title: `IOC metadata report ${i}`, vendor: "talos", path: `reports/${i}.txt`, source_url: "https://example.test/report", article_url: null, published_at: timestamp, activity_at: timestamp, collected_at: timestamp, commit: "a".repeat(40), blob: "b".repeat(40), parser_version: "1", license: "CC0-1.0", license_url: "https://example.test/license", attribution: "Cisco Talos", indicator_count: 2, types: ["domain"], warnings: [], withdrawn: false })), total: 20, page: 1, page_size: 20, sources: [], unique_indicators: 40, recent_indicators: 0, generated_at: timestamp } });
    if (path.endsWith("/status")) return route.fulfill({ json: { generated_at: timestamp, sources: [], next_refresh_at: null } });
    return route.fulfill({ json: {} });
  });
  return { requests, errors };
}

for (const width of [390, 1024, 1280]) {
  test(`compact brief, unified options and selection-only actions at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const { requests, errors } = await mocks(page);
    await page.goto("/threat-feed");
    const brief = page.getByRole("region", { name: "Since your last visit" });
    await expect(brief.getByLabel("News published: 10", { exact: true })).toBeVisible();
    await expect(brief.getByRole("button", { name: "Mark caught up" })).toBeHidden();
    expect((await brief.boundingBox())!.height).toBeLessThan(width < 640 ? 190 : 140);
    const toolbar = page.getByRole("region", { name: "Feed toolbar" });
    await expect(toolbar.getByLabel("News source", { exact: true })).toBeVisible();
    await expect(toolbar.getByLabel("Saved filter presets")).toBeHidden();
    await toolbar.getByText("More options", { exact: true }).click();
    await toolbar.getByText("Filter presets · Browser-local", { exact: true }).click();
    await expect(toolbar.getByLabel("Saved filter presets")).toBeVisible();
    await toolbar.getByText("More options", { exact: true }).click();
    await expect(page.getByRole("button", { name: "Save selected", exact: true })).toHaveCount(0);
    const select = page.getByRole("checkbox", { name: "Select Readable report 1", exact: true });
    await expect(select).toBeEnabled(); await select.focus(); await page.keyboard.press("Space");
    const actions = page.getByRole("region", { name: "Report selection" });
    await expect(actions.getByRole("button", { name: "Save selected", exact: true })).toBeVisible();
    await expect(page.getByRole("checkbox", { name: "Select current page" })).toHaveJSProperty("indeterminate", true);
    await actions.getByRole("button", { name: "Clear selection", exact: true }).click();
    await expect(page.getByRole("checkbox", { name: "Select current page" })).toBeFocused();
    await expect(actions.getByRole("button", { name: "Save selected", exact: true })).toHaveCount(0);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await expect(toolbar.getByLabel("Topic", { exact: true })).toHaveCSS("transition-duration", "1e-05s");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(requests.filter((path) => path.endsWith("/home"))).toHaveLength(1);
    expect(requests.some((path) => /investigate|poc\/lookup|refresh/.test(path))).toBe(false);
    expect(errors).toEqual([]);
    if (process.env.THREATLENS_VISUAL_CHECK === "1") { await page.evaluate(() => scrollTo(0, 0)); await page.screenshot({ path: `test-results/feed-refined-${width}.png`, fullPage: true }); }
  });
}

for (const view of ["news", "iocs"] as const) {
  test(`${view} sticky headings track the search header and visible columns`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 844 });
    const { errors } = await mocks(page);
    await page.goto(`/threat-feed?tab=${view}`);
    const table = page.getByRole("table");
    await expect(table).toBeVisible();
    const scroll = () => table.evaluate((node) => scrollTo(0, node.getBoundingClientRect().top + scrollY + 100));
    await scroll();
    const floating = page.locator(".floating-table-heading");
    await expect(floating).toBeVisible();
    const header = page.getByRole("banner", { name: "Threat Feed search controls" });
    await expect.poll(async () => {
      const current = await floating.boundingBox(), pinned = await header.boundingBox();
      return current && pinned ? Math.abs(current.y - pinned.y - pinned.height) : Infinity;
    }).toBeLessThan(1);
    await expect(page.locator(".floating-table-headings")).toHaveAttribute("aria-hidden", "true");
    await expect(page.locator(".floating-table-headings")).toHaveAttribute("inert", "");
    const toolbar = page.getByRole("region", { name: "Feed toolbar" });
    await toolbar.getByText("More options", { exact: true }).click();
    await toolbar.getByText("Table display options", { exact: true }).click();
    await toolbar.getByRole("checkbox", { name: view === "news" ? "Source" : "Vendor", exact: true }).uncheck();
    await toolbar.getByText("More options", { exact: true }).click();
    await scroll();
    await expect(floating).toBeVisible();
    await expect(floating).not.toContainText(view === "news" ? "Source" : "Vendor");
    await page.setViewportSize({ width: 1440, height: 844 });
    await expect.poll(async () => {
      const current = await floating.boundingBox(), original = await table.boundingBox();
      return current && original ? Math.abs(current.x - original.x) : Infinity;
    }).toBeLessThan(1);
    expect(errors).toEqual([]);
  });
}
