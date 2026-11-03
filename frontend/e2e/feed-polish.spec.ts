import { expect, test, type Page } from "@playwright/test";
import { mockOwnerSignIn } from "./owner-auth";

const now = new Date().toISOString();
const title = "Synthetic vendor advisory with a deliberately long headline about affected products, published security updates, and source-reported intelligence for analysts reviewing the complete report";
const article = { id: "polish-news", title, source_id: "talos", source_name: "Cisco Talos", source_kind: "rss", url: "https://example.test/report", excerpt: "Synthetic publisher metadata", summary: "A synthetic summary for layout verification.", published_at: now, region: "global", region_reasons: ["No explicit regional targeting in source metadata"], relevance: "general", topic: "advisory", severity: null, entities: [] };
const vulnerability = { id: "CVE-2026-12345", cve_id: "CVE-2026-12345", title, description: "Synthetic source-provided description.", products: ["Example product with an explicitly supplied long name"], sources: ["NVD"], scores: [], severity: null, published_at: now, updated_at: now, activity_at: now, references: [], reports: [], reported_zero_day: false, known_exploited: false, kev_added_at: null };
const ioc = { id: "polish-ioc", title: "Synthetic vendor IOC report", vendor: "talos", path: "reports/indicators.txt", source_url: "https://example.test/iocs", article_url: null, published_at: now, activity_at: now, collected_at: now, commit: "a".repeat(40), blob: "b".repeat(40), parser_version: "1", license: "CC0", license_url: "https://example.test/license", attribution: "Cisco Talos", indicator_count: 0, types: [], warnings: [], withdrawn: false };

async function fixtures(page: Page) {
  const requests: string[] = [], errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname; requests.push(path);
    if (path.endsWith("/home")) return route.fulfill({ json: { generated_at: now, summary: { regions: { global: { total: 10, recent: 10 }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, critical: 0, new_iocs: 0, source_errors: 0, last_refreshed_at: now }, sections: { global: { total: 10, items: Array.from({ length: 10 }, (_, i) => ({ ...article, id: i ? `news-${i}` : article.id })) }, malaysia: { total: 0, items: [] }, southeast_asia: { total: 0, items: [] } } } });
    if (path.endsWith(`/items/${article.id}`)) return route.fulfill({ json: article });
    if (path.endsWith("/vulnerabilities")) return route.fulfill({ json: { items: [vulnerability], total: 1, page: 1, page_size: 20, sources: ["NVD"], published_24h: 1, zero_days_24h: 0, kev_added_24h: 0, last_synced_at: now, sync_status: "current", generated_at: now } });
    if (path.endsWith(`/vulnerabilities/${vulnerability.id}`)) return route.fulfill({ json: vulnerability });
    if (path.endsWith("/ioc-reports")) return route.fulfill({ json: { items: [ioc], total: 1, page: 1, page_size: 20, sources: [], unique_indicators: 0, recent_indicators: 0, generated_at: now } });
    if (path.endsWith("/activity")) return route.fulfill({ status: 503, json: {} });
    return route.fulfill({ json: { items: [], sources: [], links: [], cves: [] } });
  });
  return { requests, errors };
}
async function screenshot(page: Page, name: string) {
  if (process.env.THREATLENS_VISUAL_CHECK === "1") {
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: `test-results/polish-${name}.png`, fullPage: true });
    if (name.startsWith("news")) await page.screenshot({ path: `test-results/polish-${name}-viewport.png` });
  }
}

for (const width of [390, 1024, 1440]) {
  test(`feed hierarchy, long-title preview and adaptive navigation at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const { requests, errors } = await fixtures(page);
    await page.goto("/threat-feed");
    const stats = page.getByRole("region", { name: "News activity" }), toolbar = page.getByRole("region", { name: "Feed toolbar" });
    await expect(stats).toBeVisible(); await expect(toolbar).toBeVisible();
    expect((await stats.boundingBox())!.y).toBeLessThan((await toolbar.boundingBox())!.y);
    await expect(toolbar.getByRole("button", { name: "Reload saved data", exact: true })).toBeVisible();
    const table = page.getByRole("table", { name: "Latest 10 news" });
    const row = table.getByRole("row").filter({ has: page.getByRole("link", { name: title, exact: true }) }).first();
    const headline = row.getByRole("link", { name: title, exact: true });
    expect((await headline.boundingBox())!.height).toBeLessThanOrEqual(49);
    const before = (await table.boundingBox())!.x;
    await table.evaluate((node) => scrollTo(0, node.getBoundingClientRect().top + scrollY + 120));
    const views = page.getByRole("navigation", { name: "Threat Feed views" });
    await expect(views).toHaveAttribute("data-docked", String(width >= 1280));
    expect((await table.boundingBox())!.x).toBe(before);
    await row.getByRole("button", { name: `Preview ${title}`, exact: true }).focus(); await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: title });
    await expect(dialog.getByRole("heading", { name: title, exact: true })).toBeVisible();
    await page.keyboard.press("Escape"); await expect(dialog).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await screenshot(page, `news-${width}`);
    await page.goto("/threat-feed?tab=vulnerabilities");
    await expect(page.getByRole("columnheader", { name: "CVE / Title", exact: true })).toBeVisible();
    expect((await page.getByRole("region", { name: "Vulnerability activity" }).boundingBox())!.y).toBeLessThan((await toolbar.boundingBox())!.y);
    await screenshot(page, `vulnerabilities-${width}`);
    await page.getByRole("link", { name: vulnerability.cve_id, exact: true }).click();
    const facts = page.getByRole("complementary", { name: "Vulnerability facts" });
    await expect(facts).toBeVisible(); await expect(page.getByRole("heading", { name: "Description", exact: true })).toBeVisible();
    await screenshot(page, `detail-${width}`);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.goto("/threat-feed?tab=iocs");
    await expect(page.getByRole("link", { name: ioc.title, exact: true })).toBeVisible();
    expect(await page.getByText("Source coverage and synchronization", { exact: true }).evaluate((node) => (node.parentElement as HTMLDetailsElement).open)).toBe(false);
    await screenshot(page, `iocs-${width}`);
    await mockOwnerSignIn(page); await page.goto(`/threat-feed?tab=poc&cve=${vulnerability.cve_id}`);
    await expect(page.getByRole("textbox", { name: "CVE identifier", exact: true })).toHaveValue(vulnerability.cve_id);
    await expect(page.getByText("Not locally tested", { exact: false })).toBeVisible();
    await screenshot(page, `poc-${width}`);
    expect(requests.some((path) => /investigate|poc\/lookup|\/refresh$/.test(path))).toBe(false);
    expect(errors).toEqual([]);
  });
}

test("narrow layout with enlarged text keeps controls and detail actions usable", async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 900 }); await fixtures(page);
  await page.goto("/threat-feed");
  await expect(page.getByRole("heading", { name: "Latest 10 news", exact: true })).toBeVisible();
  await page.evaluate(() => { document.documentElement.style.fontSize = "20px"; });
  await expect(page.getByRole("button", { name: "Reload saved data", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("link", { name: title, exact: true }).first().click();
  await expect(page.getByRole("link", { name: "Read at publisher ↗", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save locally", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
