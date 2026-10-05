import { expect, test, type Page } from "@playwright/test";

const now = new Date().toISOString();
const id = "11111111-1111-4111-8111-111111111111";
async function signIn(page: Page) {
  const user = { id, aud: "authenticated", role: "authenticated", email: "test@example.test", app_metadata: {}, user_metadata: {}, created_at: now };
  const session = { access_token: "mock-access-token", refresh_token: "mock-refresh-token", expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, token_type: "bearer", user };
  await page.context().addCookies([{ name: "sb-127-auth-token", value: `base64-${Buffer.from(JSON.stringify(session)).toString("base64url")}`, url: "http://localhost:31987" }]);
  await page.route("http://127.0.0.1:54321/auth/v1/**", (route) => route.fulfill({ json: user }));
}
test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", (route) => route.fulfill({ json: { status: "ok" } }));
});

test("feed Back links and browser forward restore the original URL and row position", async ({ page }) => {
  const records = Array.from({ length: 20 }, (_, index) => ({ id: `CVE-2026-${20000 + index}`, cve_id: `CVE-2026-${20000 + index}`, title: "Source-reported vulnerability", description: "Compact metadata", published_at: now, activity_at: now, updated_at: now, products: [], scores: [], severity: "critical", sources: ["NVD"], references: [], reports: [], reported_zero_day: false, known_exploited: false }));
  await page.route("**/api/v1/threat-feed/vulnerabilities?*", (route) => route.fulfill({ json: { items: records, total: 40, page: 2, page_size: 20, sources: ["NVD"], published_24h: 20, zero_days_24h: 0, kev_added_24h: 0, sync_status: "current", last_synced_at: now, generated_at: now } }));
  await page.route("**/api/v1/threat-feed/vulnerabilities/CVE-2026-20012", (route) => route.fulfill({ json: records[12] }));
  await page.goto("/threat-feed?tab=vulnerabilities&severity=critical&page=2");
  const row = page.getByRole("link", { name: "CVE-2026-20012", exact: true }).locator("xpath=ancestor::tr");
  await row.scrollIntoViewIfNeeded();
  const offset = (await row.boundingBox())!.y;
  const originalUrl = page.url();
  await row.getByRole("link").click();
  await expect(page.getByRole("heading", { name: "Description", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "← Back to Vulnerabilities", exact: true }).click();
  await expect(page).toHaveURL(originalUrl);
  await expect.poll(async () => Math.abs(((await row.boundingBox())?.y ?? -1000) - offset)).toBeLessThan(3);
  expect(await page.evaluate(() => Boolean(history.state.threatlensListEntry))).toBe(true);
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Description", exact: true })).toBeVisible();
  await page.goForward();
  await expect(page).toHaveURL(originalUrl);
  await expect.poll(async () => Math.abs(((await row.boundingBox())?.y ?? -1000) - offset)).toBeLessThan(3);
  expect(await page.evaluate(() => Object.keys(history.state).some((key) => key === "__NA"))).toBe(true);
  expect(await page.evaluate(() => Object.keys(localStorage).some((key) => key.includes("list-recovery")))).toBe(false);
});

for (const kind of ["workspace", "cases"] as const) {
  test(`${kind} preserves URL filters and scroll without rerunning intelligence`, async ({ page }) => {
    await signIn(page);
    let investigations = 0;
    await page.route("**/api/v1/investigate**", (route) => { investigations++; return route.abort(); });
    const records = Array.from({ length: 25 }, (_, index) => ({ id: index === 12 ? id : `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`, title: `Saved record ${index}`, summary: "Existing snapshot", status: "open", severity: 3, investigation_type: "domain", priority: "high", owner: "", tags: [], metadata: {}, created_at: now, updated_at: now, linked_workspace_ids: [], notes: [], investigation_summary: null, investigation_snapshot: null, correlation_summary: null, detection_package: null }));
    await page.route(`**/api/v1/${kind}*`, (route) => route.fulfill({ json: { [kind === "workspace" ? "investigations" : "cases"]: records, total: records.length } }));
    await page.route(`**/api/v1/${kind}/${id}`, (route) => route.fulfill({ json: records[12] }));
    const filter = kind === "workspace" ? "q=Saved&status=open&severity=3" : "title=Saved&status=open&priority=high";
    await page.goto(`/${kind}?${filter}`);
    const target = page.getByRole("link", { name: /Saved record 12/ });
    await expect(target).toBeVisible();
    await target.scrollIntoViewIfNeeded();
    const row = target.locator("xpath=ancestor::li");
    const offset = (await row.boundingBox())!.y;
    const originalUrl = page.url();
    await target.click();
    await expect(page.getByRole("heading", { name: "Saved record 12", exact: true })).toBeVisible();
    await page.getByRole("link", { name: kind === "workspace" ? "← Back to Workspace" : "← Back to Cases", exact: true }).click();
    await expect(page).toHaveURL(originalUrl);
    await expect(page.getByRole("combobox", { name: "Filter by status" })).toHaveValue("open");
    await expect.poll(async () => Math.abs(((await row.boundingBox())?.y ?? -1000) - offset)).toBeLessThan(3);
    expect(investigations).toBe(0);
    if (kind === "workspace") {
      // A pending restoration must not fight a user's own scroll.
      await target.click();
      await expect(page.getByRole("heading", { name: "Saved record 12", exact: true })).toBeVisible();
      let release!: () => void;
      const waiting = new Promise<void>((resolve) => { release = resolve; });
      await page.route("**/api/v1/workspace?*", async (route) => { await waiting; await route.fulfill({ json: { investigations: records, total: records.length } }); });
      await page.getByRole("link", { name: "← Back to Workspace", exact: true }).click();
      await expect(page.getByLabel("Loading saved investigations")).toBeVisible();
      await page.mouse.wheel(0, -3000);
      release();
      await expect(target).toBeVisible();
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBeLessThan(200);
    }
  });
}
