import { expect, test } from "@playwright/test";

const now = new Date().toISOString();
const report = { id: "one", vendor: "talos", title: "Example malware indicators", path: "2026/iocs.txt", source_url: "https://github.com/Cisco-Talos/IOCs/blob/main/2026/iocs.txt", article_url: null, published_at: null, activity_at: now, collected_at: now, commit: "a".repeat(40), blob: "b".repeat(40), parser_version: "1.0", license: "CC0-1.0", license_url: "https://github.com/Cisco-Talos/IOCs/blob/main/LICENSE", attribution: "Cisco Talos; source-reported", indicator_count: 2, types: ["domain", "ipv4"], warnings: [], withdrawn: false };
const items = [{ id: "domain", type: "domain", value: "evil.test", original: "evil[.]test", disposition: "source-reported", verified: false }, { id: "ip", type: "ipv4", value: "192.0.2.1", original: "192.0.2.1", disposition: "source-reported", verified: false }];
test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/ioc-reports/one")) return route.fulfill({ json: { report, indicators: items } });
    if (url.pathname.endsWith("/ioc-reports")) return route.fulfill({ json: { items: url.searchParams.get("vendor") === "eset" ? [] : [report], total: 1, page: 1, page_size: 20, unique_indicators: 2, recent_indicators: 2, sources: [{ vendor: "sophoslabs", name: "SophosLabs", url: "https://github.com/sophoslabs/IoCs", enabled: false, license: "Redistribution not verified", status: "license_pending", last_success_at: null, pending: 0, skipped: 0, safe_error: "Import disabled pending redistribution review.", next_attempt_at: null }], generated_at: now } });
    if (url.pathname.endsWith("/indicators")) return route.fulfill({ json: { items: items.map((item) => ({ ...item, vendors: ["talos"], reports: [report], activity_at: now })), total: 2, page: 1, page_size: 20 } });
    if (url.pathname.endsWith("/refresh")) return route.fulfill({ json: { status: "cooldown", next_refresh_at: now } });
    return route.fulfill({ json: { status: "ok" } });
  });
});

test("public IOC reports, filters, provenance, export and explicit investigation handoff", async ({ page }) => {
  const errors: string[] = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/threat-feed?tab=iocs");
  await expect(page.getByRole("link", { name: "Example malware indicators" })).toBeVisible();
  await expect(page.getByText("Import disabled pending redistribution review.")).toBeVisible();
  await page.getByRole("button", { name: "Refresh IOC reports" }).click();
  await expect(page.getByRole("main").getByRole("status").filter({ hasText: "cooling down" })).toBeVisible();
  await page.getByRole("button", { name: "Indicators", exact: true }).click();
  await expect(page).toHaveURL(/view=indicators/);
  await expect(page.getByText("evil[.]test", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Example malware indicators" }).first().click();
  // The dev server compiles this detail route on its first visit.
  await expect(page).toHaveURL(/\/threat-feed\/ioc-reports\/one$/, { timeout: 15000 });
  await expect(page.getByRole("heading", { name: report.title })).toBeVisible();
  await expect(page.getByRole("link", { name: "Official source file" })).toHaveAttribute("href", report.source_url);
  await expect(page.getByRole("link", { name: "Investigate", exact: true }).first()).toHaveAttribute("href", "/?q=evil.test");
  await page.getByRole("button", { name: "Select current page" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export selected CSV" }).click();
  expect((await download).suggestedFilename()).toBe("threatlens-iocs-one.csv");
  await page.getByRole("button", { name: "Bookmark report" }).click();
  expect(await page.evaluate(() => localStorage.getItem("threatlens.feed.iocs.bookmarks"))).toContain("one");
  expect(errors).toEqual([]);
});

test("IOC list uses cached fallback and remains responsive on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/threat-feed?tab=iocs");
  await expect(page.getByRole("link", { name: report.title })).toBeVisible();
  await page.route("**/api/v1/threat-feed/ioc-reports?*", (route) => route.abort());
  await page.reload();
  await expect(page.getByRole("link", { name: report.title })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Could not update" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: "test-results/ioc-reports-mobile.png", fullPage: true });
});
