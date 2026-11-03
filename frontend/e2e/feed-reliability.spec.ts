import { expect, test, type Page } from "@playwright/test";

const now = new Date().toISOString();
const article = { id: "reliable-news", title: "Stored security report", source_id: "talos", source_name: "Cisco Talos", source_kind: "rss", excerpt: "Publisher metadata", summary: "Publisher metadata", url: "https://example.test/report", published_at: now, region: "global", relevance: "general", region_reasons: [], topic: "research", severity: null, entities: [] };
const record = { id: "CVE-2026-12345", cve_id: "CVE-2026-12345", title: "Stored vulnerability", description: "Published metadata", products: ["Example product"], sources: ["NVD"], scores: [], severity: null, published_at: now, activity_at: now, updated_at: now, references: [], reports: [], known_exploited: false, reported_zero_day: false, kev_added_at: null };
const home = { generated_at: now, summary: { regions: { global: { total: 1, recent: 1 }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, new_iocs: 0, critical: 0, source_errors: 0, last_refreshed_at: now, next_refresh_at: null }, sections: { global: { items: [article], total: 1 }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } } };
const vulnerabilities = { generated_at: now, items: [record], total: 1, page: 1, page_size: 20, published_24h: 1, zero_days_24h: 0, kev_added_24h: 0, sources: ["NVD"], sync_status: "current", last_synced_at: now };
async function mock(page: Page) {
  const counts = { home: 0, vulnerabilities: 0, status: 0, refresh: 0 };
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname.split("/").at(-1);
    if (path === "home" || path === "vulnerabilities") {
      counts[path]++;
      expect(route.request().headers().authorization).toBeUndefined();
      return route.fulfill({ json: path === "home" ? home : vulnerabilities });
    }
    if (path === "status") { counts.status++; return route.fulfill({ json: { generated_at: now, next_refresh_at: null, sources: [] } }); }
    if (path === "refresh") { counts.refresh++; return route.fulfill({ json: { status: "cooldown", next_refresh_at: now } }); }
    if (path === "activity") return route.fulfill({ status: 503, json: {} });
    return route.fulfill({ json: {} });
  });
  return { counts, errors };
}

for (const tab of ["news", "vulnerabilities"] as const) {
  const rowName = tab === "news" ? article.title : record.cve_id;
  const endpoint = tab === "news" ? "home" : "vulnerabilities";
  test(`${tab}: fresh cache avoids reads; reload reads stored data and diagnostics are lazy`, async ({ page }) => {
    const { counts, errors } = await mock(page);
    await page.goto(`/threat-feed?tab=${tab}`);
    await expect(page.getByRole("link", { name: rowName, exact: true })).toBeVisible();
    expect(counts.status).toBe(0);
    const reads = counts[endpoint];
    await page.reload();
    await expect(page.getByRole("status").filter({ hasText: "Showing cached data" })).toBeVisible();
    expect(counts[endpoint]).toBe(reads);
    await page.getByRole("button", { name: "Reload saved data", exact: true }).click();
    await expect.poll(() => counts[endpoint]).toBe(reads + 1);
    expect(counts.refresh).toBe(0);
    await page.getByText("Collection freshness and coverage", { exact: false }).click();
    await expect.poll(() => counts.status).toBe(1);
    await expect(page.getByText("Next public refresh eligibility:", { exact: false })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test(`${tab}: malformed or failed reload retains good rows and cached data`, async ({ page }) => {
    const { errors } = await mock(page);
    await page.goto(`/threat-feed?tab=${tab}`);
    const row = page.getByRole("link", { name: rowName, exact: true }); await expect(row).toBeVisible();
    await page.route(`**/api/v1/threat-feed/${endpoint}?*`, (route) => route.fulfill({ json: { items: [{ id: "broken" }] } }));
    await page.getByRole("button", { name: "Reload saved data", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "last available reports" })).toBeVisible();
    await expect(row).toBeVisible();
    await page.reload();
    await expect(row).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "Showing cached data" })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test(`${tab}: slow reads stop at the deadline and never collect or retry automatically`, async ({ page }) => {
    const { counts } = await mock(page);
    await page.goto(`/threat-feed?tab=${tab}`);
    await expect(page.getByRole("link", { name: rowName, exact: true })).toBeVisible();
    await page.clock.install();
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    await page.route(`**/api/v1/threat-feed/${endpoint}?*`, async (route) => { await pending; await route.abort().catch(() => undefined); });
    const started = page.waitForRequest((request) => request.url().includes(`/threat-feed/${endpoint}?`) && request.url().includes("fresh=true"));
    await page.getByRole("button", { name: "Reload saved data", exact: true }).click(); await started;
    await page.clock.fastForward(4100);
    await expect(page.getByRole("status").filter({ hasText: "taking longer than usual" })).toBeVisible();
    await page.clock.fastForward(8000);
    await expect(page.getByRole("status").filter({ hasText: "timed out" })).toBeVisible();
    await expect(page.getByRole("link", { name: rowName, exact: true })).toBeVisible();
    expect(counts.refresh).toBe(0); finish();
  });
}

test("failed source collection never announces a successful vulnerability refresh", async ({ page }) => {
  await mock(page);
  await page.route("**/api/v1/threat-feed/refresh", (route) => route.fulfill({ json: { status: "failed", sources_succeeded: 0, sources_attempted: 3, items_added: 0, next_refresh_at: now } }));
  await page.goto("/threat-feed?tab=vulnerabilities");
  await expect(page.getByRole("columnheader", { name: "CVE / Title", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Refresh sources", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Sources could not be refreshed" })).toBeVisible();
  await expect(page.getByText("Saved vulnerability data reloaded after collection.", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: record.cve_id, exact: true })).toBeVisible();
});
