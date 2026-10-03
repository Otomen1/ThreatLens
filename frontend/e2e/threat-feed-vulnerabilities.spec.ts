import { expect, test } from "@playwright/test";

const now = new Date().toISOString();
const report = { id: "news-one", source_id: "mycert", source_name: "MyCERT", source_kind: "rss", title: "Malaysia security advisory", excerpt: "Apply the update", summary: "Apply the update", url: "https://example.test/news", published_at: now, collected_at: now, region: "malaysia", relevance: "high", region_reasons: ["Official Malaysian source"], topic: "advisory", severity: null, entities: [] };
const vulnerability = { id: "CVE-2026-12345", cve_id: "CVE-2026-12345", title: "Example browser vulnerability", description: "A source-reported browser vulnerability.", published_at: now, activity_at: now, updated_at: now, products: ["Example Browser"], scores: [{ source: "NVD", version: "3.1", score: 9.8, severity: "critical" }], severity: "critical", sources: ["NVD", "MyCERT"], references: ["https://nvd.nist.gov/vuln/detail/CVE-2026-12345"], reports: [{ ...report, zero_day: true }], reported_zero_day: true, known_exploited: true, kev_added_at: now };

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/threat-feed/home")) return route.fulfill({ json: { summary: { regions: { global: { total: 0, recent: 0 }, malaysia: { total: 1, recent: 1 }, southeast_asia: { total: 0, recent: 0 } }, new_iocs: 0, critical: 0, last_refreshed_at: now, source_errors: 0 }, sections: { global: { items: [], total: 0 }, malaysia: { items: [report], total: 1 }, southeast_asia: { items: [], total: 0 } }, generated_at: now } });
    if (url.pathname.endsWith("/threat-feed/items")) return route.fulfill({ json: { items: [report], total: 1, page: 1, page_size: 20 } });
    if (url.pathname.endsWith("/threat-feed/refresh")) return route.fulfill({ json: { status: "cooldown", next_refresh_at: now } });
    if (url.pathname.endsWith("/vulnerabilities/CVE-2026-12345")) return route.fulfill({ json: vulnerability });
    if (url.pathname.endsWith("/vulnerabilities")) return route.fulfill({ json: { items: [vulnerability], total: 1, page: 1, page_size: 20, sources: ["NVD", "MyCERT"], published_24h: 1, zero_days_24h: 1, kev_added_24h: 1, last_synced_at: now, sync_status: "current", generated_at: now } });
    return route.fulfill({ json: { status: "ok" } });
  });
});

test("public News and Vulnerabilities tabs, filters, details and investigation handoff", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/threat-feed");
  await expect(page.getByRole("heading", { name: "Global", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Malaysia", exact: true })).toBeVisible();
  await page.getByRole("navigation", { name: "Threat Feed views" }).getByRole("link", { name: "Vulnerabilities" }).click();
  await expect(page.getByRole("link", { name: "CVE-2026-12345", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Reported zero-days", exact: true }).click();
  await expect(page).toHaveURL(/category=zero_days/);
  await page.getByRole("combobox", { name: "Vulnerability severity" }).selectOption("critical");
  await expect(page).toHaveURL(/severity=critical/);
  await page.reload();
  await expect(page.getByRole("combobox", { name: "Vulnerability severity" })).toHaveValue("critical");
  await page.getByRole("button", { name: "Refresh feed" }).click();
  await expect(page.getByRole("status").filter({ hasText: /cooling down/ })).toBeVisible();
  await page.getByRole("link", { name: "CVE-2026-12345", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Description", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Investigate CVE" })).toHaveAttribute("href", "/?q=CVE-2026-12345");
  expect(await page.evaluate(() => localStorage.getItem("threatlens.feed.vulnerabilities.viewed"))).toContain("CVE-2026-12345");
  expect(errors).toEqual([]);
});

test("regional News view all and vulnerability stale fallback", async ({ page }) => {
  await page.goto("/threat-feed?region=malaysia");
  await expect(page.getByRole("heading", { name: "Malaysia", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Global", exact: true })).toHaveCount(0);
  await page.goto("/threat-feed?tab=vulnerabilities");
  await expect(page.getByRole("link", { name: "CVE-2026-12345", exact: true })).toBeVisible();
  await page.route("**/api/v1/threat-feed/vulnerabilities?*", (route) => route.abort());
  await page.reload();
  await expect(page.getByRole("link", { name: "CVE-2026-12345", exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /last available/ })).toBeVisible();
});

test("unassigned CVE and missing scores remain readable on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/v1/threat-feed/vulnerabilities?*", (route) => route.fulfill({ json: {
    items: [{ ...vulnerability, id: "report-one", cve_id: null, title: "Vendor reports a zero-day", products: [], scores: [], severity: null, known_exploited: false }],
    total: 1, page: 1, page_size: 20, sources: ["MyCERT"], published_24h: 0, zero_days_24h: 1, kev_added_24h: 0, last_synced_at: now, sync_status: "partial", generated_at: now,
  } }));
  await page.goto("/threat-feed?tab=vulnerabilities");
  await expect(page.getByRole("link", { name: "CVE not assigned" })).toBeVisible();
  await expect(page.getByText("Not rated", { exact: true })).toBeAttached();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: "test-results/feed-vulnerabilities-mobile.png", fullPage: true });
});
