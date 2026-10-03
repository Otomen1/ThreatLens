import { expect, test } from "@playwright/test";

test("stored search, exact related links, local bookmarks and prepared PoC lookup", async ({ page }) => {
  const now = new Date().toISOString();
  const cve = "CVE-2026-1234";
  const reference = { id: "news-one", kind: "news", title: "Malaysian phishing report", href: "/threat-feed/news-one", source: "Talos", activity_at: now };
  const news = { id: "news-one", source_name: "Talos", published_at: now, title: reference.title, topic: "phishing", url: "https://example.test/report", summary: "Phishing targets Malaysian banks", region: "malaysia", region_reasons: ["Explicitly mentions Malaysia"], entities: [], targeting_evidence: [{ region: "malaysia", source: "Talos", field: "title", excerpt: "Phishing targets Malaysian banks", related_report: false }] };
  const errors: string[] = []; let liveLookups = 0;
  page.on("pageerror", (e) => errors.push(e.message));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.includes("/poc/lookup")) liveLookups++;
    if (path.endsWith("/threat-feed/status")) return route.fulfill({ json: { generated_at: now, next_refresh_at: now, sources: [{ id: "talos", name: "Talos", collection: "iocs", state: "partial", stale: true, pending: 1, last_attempt_at: now, last_success_at: now, error: null, next_eligible_at: now }] } });
    if (path.endsWith("/threat-feed/search")) return route.fulfill({ json: { generated_at: now, poc_cve: cve, groups: { news: { items: [reference], total: 1, page: 1, page_size: 20 }, vulnerability: { items: [], total: 0, page: 1, page_size: 20 }, ioc: { items: [], total: 0, page: 1, page_size: 20 } } } });
    if (path.endsWith("/items/news-one")) return route.fulfill({ json: news });
    if (path.includes("/related/news/news-one")) return route.fulfill({ json: { cves: [cve], items: [{ record: { ...reference, id: cve, kind: "vulnerability", title: cve, href: `/threat-feed/vulnerabilities/${cve}` }, reason: "References the same CVE", supporting_values: [cve] }] } });
    return route.fulfill({ json: { status: "ok" } });
  });
  await page.goto(`/threat-feed?view=search&q=${cve}`);
  await expect(page.getByRole("heading", { name: "Search results" })).toBeVisible();
  await page.getByRole("link", { name: reference.title }).click();
  await expect(page.getByRole("heading", { name: reference.title })).toBeVisible({ timeout: 15000 });
  await expect(page.getByText(/Source reports Malaysia targeting/)).toBeVisible();
  await expect(page.getByText(/References the same CVE/)).toBeVisible();
  await page.getByRole("button", { name: "Save locally" }).click();
  await page.goto("/threat-feed?view=saved");
  await expect(page.getByRole("link", { name: reference.title })).toBeVisible();
  await page.getByRole("button", { name: "Clear all saved" }).click();
  await expect(page.getByRole("button", { name: "Confirm clear" })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByRole("link", { name: reference.title })).toBeVisible();
  await page.getByRole("link", { name: reference.title }).click();
  await page.getByRole("link", { name: `Find PoC & Tools: ${cve}` }).click();
  await expect(page).toHaveURL(new RegExp(`tab=poc&cve=${cve}`));
  expect(liveLookups).toBe(0); expect(errors).toEqual([]);
});
