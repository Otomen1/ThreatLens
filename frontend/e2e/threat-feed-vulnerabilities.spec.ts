import { expect, test } from "@playwright/test";

const now = new Date().toISOString();
const report = { id: "news-one", source_id: "mycert", source_name: "MyCERT", source_kind: "rss", title: "Malaysia security advisory", excerpt: "Apply the update", summary: "Apply the update", url: "https://example.test/news", published_at: now, collected_at: now, region: "malaysia", relevance: "high", region_reasons: ["Official Malaysian source"], topic: "advisory", severity: null, entities: [] };
const vulnerability = { id: "CVE-2026-12345", cve_id: "CVE-2026-12345", title: "Example browser vulnerability", description: "A source-reported browser vulnerability.", published_at: now, activity_at: now, updated_at: now, products: ["Example Browser"], scores: [{ source: "NVD", version: "3.1", score: 9.8, severity: "critical" }], severity: "critical", sources: ["NVD", "MyCERT"], references: ["https://nvd.nist.gov/vuln/detail/CVE-2026-12345"], reports: [{ ...report, zero_day: true }], reported_zero_day: true, known_exploited: true, kev_added_at: now };

for (const width of [1280, 2269, 390]) {
  test(`feed search controls stay below navigation while scrolling at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.route("**/api/v1/threat-feed/vulnerabilities?*", (route) => route.fulfill({ json: {
      items: Array.from({ length: 20 }, (_, index) => ({ ...vulnerability, id: `CVE-2026-${20000 + index}`, cve_id: `CVE-2026-${20000 + index}` })),
      total: 20, page: 1, page_size: 20, sources: ["NVD"], published_24h: 20, zero_days_24h: 0, kev_added_24h: 0, last_synced_at: now, sync_status: "current", generated_at: now,
    } }));
    const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
    await page.goto("/threat-feed?tab=vulnerabilities");
    await expect(page.getByRole("link", { name: "CVE-2026-20000", exact: true })).toBeVisible();
    const originalTable = await page.getByRole("table").boundingBox();
    const header = page.getByRole("banner", { name: "Threat Feed search controls" });
    const expandedHeader = await header.boundingBox();
    await page.evaluate(() => window.scrollTo(0, 1000));
    await expect.poll(async () => (await header.boundingBox())?.y).toBe(56);
    await expect(header).toHaveAttribute("data-compact", "true");
    expect((await header.boundingBox())!.height).toBeLessThan(expandedHeader!.height);
    if (width >= 1024) await expect(page.locator(".floating-table-heading")).toBeVisible();
    expect(await page.locator(".floating-table-headings").getAttribute("aria-hidden")).toBe("true");
    const nav = await page.getByRole("navigation", { name: "Primary navigation" }).boundingBox();
    const bounds = await header.boundingBox();
    expect(bounds!.y).toBeGreaterThanOrEqual(nav!.y + nav!.height - 1);
    await expect(header.getByRole("heading", { name: "Threat Feed", exact: true })).toBeVisible();
    await expect(header.getByLabel("Search all threat intelligence")).toBeVisible();
    await expect(header.getByRole("button", { name: "Search feed" })).toBeVisible();
    await expect(header.getByRole("link", { name: "Saved", exact: true })).toBeVisible();
    expect(await page.evaluate(() => window.scrollY)).toBeGreaterThan(300);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const views = page.getByRole("navigation", { name: "Threat Feed views" });
    await expect(views).toHaveAttribute("data-docked", String(width >= 1024));
    await expect(views.getByRole("link", { name: "Vulnerabilities" })).toHaveAttribute("aria-current", "page");
    if (width >= 1024) {
      // The table is inset one pixel inside its bordered container.
      await expect.poll(async () => (await views.boundingBox())?.x).toBe(originalTable!.x - 161);
      const rail = await views.boundingBox();
      expect(rail!.y).toBeGreaterThanOrEqual(bounds!.y + bounds!.height);
      await expect.poll(async () => (await page.getByRole("table").boundingBox())?.x ?? 0).toBeGreaterThanOrEqual(rail!.x + rail!.width);
      const dockedTable = await page.getByRole("table").boundingBox();
      expect(dockedTable!.x).toBe(originalTable!.x);
      expect(dockedTable!.width).toBe(originalTable!.width);
      expect(rail!.x + rail!.width + 17).toBe(dockedTable!.x);
      await views.getByRole("link", { name: "News", exact: true }).focus();
      await page.evaluate(() => window.scrollBy(0, 30));
      await expect(views.getByRole("link", { name: "News", exact: true })).toBeFocused();
      if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: `test-results/feed-side-navigation-${width}.png` });
      await page.setViewportSize({ width: 390, height: 844 });
      await expect(views).toHaveAttribute("data-docked", "false");
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.setViewportSize({ width, height: 844 });
      await expect(views).toHaveAttribute("data-docked", "true");
      await page.emulateMedia({ reducedMotion: "reduce" });
      await expect(views).toHaveCSS("animation-duration", "1e-05s");
    }
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect(header).toHaveAttribute("data-compact", "false");
    await expect(page.locator(".floating-table-heading")).toHaveCount(0);
    await expect(views).toHaveAttribute("data-docked", "false");
    await expect(views.getByRole("link", { name: "News", exact: true })).toBeVisible();
    const restoredTable = await page.getByRole("table").boundingBox();
    expect(restoredTable!.x).toBe(originalTable!.x);
    expect(restoredTable!.width).toBe(originalTable!.width);
    expect(errors).toEqual([]);
  });
}

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

test("search artwork loads once, respects reduced motion and stops after feed failure", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  let finish!: () => void;
  const pending = new Promise<void>((resolve) => { finish = resolve; });
  await page.route("**/api/v1/threat-feed/home?*", async (route) => { await pending; await route.fulfill({ status: 503, json: {} }); });
  await page.goto("/threat-feed");
  const lens = page.locator(".search-loading-lens");
  await expect(lens).toBeVisible();
  await expect(lens).toHaveCSS("animation-name", "search-loading-scan");
  await expect(page.getByRole("status").filter({ hasText: "Loading threat feed…" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: "test-results/search-loading-mobile.png" });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(lens).toHaveCSS("animation-name", "none");
  finish();
  await expect(page.getByRole("button", { name: "Retry loading feed" })).toBeVisible();
  await expect(lens).toHaveCount(0);
  await page.unroute("**/api/v1/threat-feed/home?*");
  await page.getByRole("button", { name: "Retry loading feed" }).click();
  await expect(page.getByRole("heading", { name: "Malaysia", exact: true })).toBeVisible();
  await expect(lens).toHaveCount(0);
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
  let lookups = 0;
  await page.route("**/api/v1/poc/**", (route) => { lookups++; return route.abort(); });
  await page.getByRole("link", { name: "Find PoC & Tools" }).click();
  await expect(page).toHaveURL(/tab=poc&cve=CVE-2026-12345/);
  await expect(page.getByRole("link", { name: "Sign in for PoC lookup" })).toBeVisible();
  expect(lookups).toBe(0);
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
