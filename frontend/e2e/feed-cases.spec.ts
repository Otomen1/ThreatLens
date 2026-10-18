import { expect, test, type Page } from "@playwright/test";
import { mockOwnerSignIn } from "./owner-auth";

const pageErrors = new WeakMap<Page, string[]>();
test.beforeEach(({ page }) => { const errors: string[] = []; pageErrors.set(page, errors); page.on("pageerror", (error) => errors.push(error.message)); });
test.afterEach(({ page }) => { expect(pageErrors.get(page)).toEqual([]); });

const now = new Date().toISOString();
const caseId = "00000000-0000-4000-8000-000000000003";
const news = { id: "news-case", title: "Stored campaign report", source_id: "talos", source_name: "Cisco Talos", source_kind: "rss", summary: "Stored report summary", url: "https://example.test/report", published_at: now, region: "global", region_reasons: [], relevance: "general", topic: "research", entities: [] };
const vulnerability = { id: "CVE-2026-1234", cve_id: "CVE-2026-1234", title: "Stored vulnerability", description: "Stored description", sources: ["NVD"], products: [], references: [], reports: [], scores: [], severity: null };
const ioc = { id: "ioc-case", title: "Stored IOC report", vendor: "talos", source_url: "https://example.test/iocs", path: "iocs.txt", published_at: now, activity_at: now, collected_at: now, commit: "a".repeat(40), license: "CC0", license_url: "https://example.test/license", attribution: "Cisco Talos", warnings: [], types: [], indicator_count: 0 };

async function setup(page: Page, failure = false) {
  let record = { id: caseId, title: "My personal Case", description: null, status: "open", priority: "medium", created_at: now, updated_at: now, owner: null, tags: [], notes: [], linked_workspace_ids: [], metadata: {}, feed_references: [] as { kind: string; id: string; title: string; sources: { name: string; url: string }[]; attached_at: string; attribution: string; license: string | null }[] };
  const calls: string[] = []; let saves = 0;
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname; calls.push(path);
    if (path.endsWith("/threat-feed/home")) return route.fulfill({ json: { generated_at: now, summary: { regions: { global: { total: 1, recent: 1 }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, critical: 0, new_iocs: 0, source_errors: 0, last_refreshed_at: now }, sections: { global: { items: [news], total: 1 }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } } } });
    if (path.endsWith("/items/news-case")) return route.fulfill({ json: news });
    if (path.endsWith(`/vulnerabilities/${vulnerability.id}`)) return route.fulfill({ json: vulnerability });
    if (path.endsWith("/ioc-reports/ioc-case")) return route.fulfill({ json: { report: ioc, indicators: [] } });
    if (path.endsWith("/changes")) return route.fulfill({ json: { items: [], total: 0, page: 1, page_size: 5, limited: false } });
    if (path.endsWith("/cases")) return route.fulfill({ json: { cases: [record], total: 1 } });
    if (path === `/api/v1/cases/${caseId}`) return route.fulfill({ json: record });
    if (path === `/api/v1/cases/${caseId}/feed`) {
      expect(route.request().headers().authorization).toBe("Bearer mock-access-token");
      saves++;
      if (failure && saves === 1) return route.fulfill({ status: 503, json: { detail: "SECRET", retryable: true } });
      const key = route.request().postDataJSON() as { kind: string; id: string };
      expect(Object.keys(key).sort()).toEqual(["id", "kind"]);
      const title = key.kind === "news" ? news.title : key.kind === "ioc" ? ioc.title : vulnerability.title;
      record = { ...record, feed_references: [...record.feed_references.filter((ref) => ref.kind !== key.kind || ref.id !== key.id), { ...key, title, sources: [{ name: "Cisco Talos", url: "https://example.test/report" }], attached_at: now, attribution: "Cisco Talos", license: "CC0" }] };
      return route.fulfill({ json: record });
    }
    if (path.includes(`/cases/${caseId}/feed/`) && route.request().method() === "DELETE") { record = { ...record, feed_references: [] }; return route.fulfill({ json: record }); }
    return route.fulfill({ json: { items: [], total: 0, sources: [], links: [], cves: [], investigations: 0, open_cases: 1, draft_detections: 0 } });
  });
  return { calls, saves: () => saves };
}

test("signed-out details stay public and never request private Cases", async ({ page }) => {
  const { calls } = await setup(page);
  await page.goto("/threat-feed/news-case");
  await expect(page.getByText("as the owner to add this reference to a Case.", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add to Case", exact: true })).toHaveCount(0);
  expect(calls.some((path) => path.includes("/cases"))).toBe(false);
});

for (const [kind, path] of [["news", "/threat-feed/news-case"], ["vulnerability", "/threat-feed/vulnerabilities/CVE-2026-1234"], ["ioc", "/threat-feed/ioc-reports/ioc-case"]]) {
  test(`attach ${kind}, prevent duplicates, preserve attribution and confirm removal`, async ({ page }) => {
    if (kind === "ioc") await page.setViewportSize({ width: 390, height: 844 });
    const { calls, saves } = await setup(page);
    await mockOwnerSignIn(page);
    await page.goto(path);
    const add = page.getByRole("button", { name: "Add to Case", exact: true });
    await expect(add).toBeVisible();
    expect(calls.filter((path) => path === "/api/v1/cases")).toHaveLength(0);
    await add.click(); await page.getByLabel("Choose an existing Case").selectOption(caseId);
    expect(saves()).toBe(0);
    await page.getByRole("button", { name: "Confirm add to Case", exact: true }).click();
    await expect(page.getByRole("link", { name: "Open My personal Case" })).toBeVisible();
    await add.click(); await expect(page.getByRole("button", { name: "Already attached" })).toBeDisabled();
    expect(saves()).toBe(1);
    await page.getByRole("link", { name: "Open My personal Case" }).click();
    const section = page.getByRole("region", { name: "Feed references" });
    await expect(section.getByText("Cisco Talos · CC0", { exact: true })).toBeVisible();
    await expect(section.getByText(/Source-reported · Unverified/)).toBeVisible();
    await section.getByRole("button", { name: "Remove reference", exact: true }).click();
    await expect(section.getByRole("button", { name: "Confirm remove reference" })).toBeVisible();
    await section.getByRole("button", { name: "Keep reference" }).click();
    await expect(section.getByRole("link", { name: "Cisco Talos ↗" })).toBeVisible();
    await section.getByRole("button", { name: "Remove reference", exact: true }).click();
    await section.getByRole("button", { name: "Confirm remove reference" }).click();
    await expect(section.getByText(/Open a News, Vulnerability or IOC report/)).toBeVisible();
    expect(calls.some((path) => path.includes("/investigate") || path.includes("/poc/lookup") || path.endsWith("/refresh"))).toBe(false);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

test("failed save stays inline, never retries automatically and clears on sign-out", async ({ page }) => {
  const { saves } = await setup(page, true); await mockOwnerSignIn(page);
  await page.goto("/threat-feed/news-case");
  await page.getByRole("button", { name: "Add to Case", exact: true }).click();
  await page.getByLabel("Choose an existing Case").selectOption(caseId);
  await page.getByRole("button", { name: "Confirm add to Case", exact: true }).click();
  const inlineError = page.getByRole("region", { name: "Add feed reference to Case" }).getByRole("alert");
  await expect(inlineError).toContainText("temporarily unavailable");
  await expect(inlineError).not.toContainText("SECRET"); expect(saves()).toBe(1);
  await page.getByRole("button", { name: "Confirm add to Case", exact: true }).click();
  await expect(page.getByRole("link", { name: "Open My personal Case" })).toBeVisible(); expect(saves()).toBe(2);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("link", { name: "Open My personal Case" })).toHaveCount(0);
});

test("preview attachment stays inside the existing accessible drawer", async ({ page }) => {
  const { saves } = await setup(page); await mockOwnerSignIn(page);
  await page.goto("/threat-feed");
  await page.getByRole("button", { name: `Preview ${news.title}`, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: news.title });
  await dialog.getByRole("button", { name: "Add to Case", exact: true }).click();
  await dialog.getByLabel("Choose an existing Case").selectOption(caseId);
  await dialog.getByRole("button", { name: "Confirm add to Case" }).click();
  await expect(dialog.getByRole("link", { name: "Open My personal Case" })).toBeVisible();
  expect(saves()).toBe(1); await expect(page.getByRole("dialog")).toHaveCount(1);
  await page.keyboard.press("Escape"); await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("sign-out aborts a pending attachment and rejects late private UI", async ({ page }) => {
  await setup(page); await mockOwnerSignIn(page);
  let release!: () => void; let started!: () => void;
  const pending = new Promise<void>((resolve) => { started = resolve; });
  await page.route(`**/api/v1/cases/${caseId}/feed`, async (route) => {
    started(); await new Promise<void>((resolve) => { release = resolve; });
    await route.fulfill({ json: { id: caseId, title: "Late private Case" } }).catch(() => undefined);
  });
  await page.goto("/threat-feed/news-case");
  await page.getByRole("button", { name: "Add to Case", exact: true }).click();
  await page.getByLabel("Choose an existing Case").selectOption(caseId);
  await page.getByRole("button", { name: "Confirm add to Case" }).click(); await pending;
  await page.getByRole("button", { name: "Sign out", exact: true }).click(); release();
  await expect(page.getByRole("button", { name: "Add to Case", exact: true })).toHaveCount(0);
  await expect(page.getByText("Late private Case", { exact: false })).toHaveCount(0);
});
