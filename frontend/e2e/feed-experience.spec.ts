import { expect, test, type Page } from "@playwright/test";
import { mockOwnerAccess } from "./owner-auth";

const now = new Date().toISOString();
const news = { id: "news-preview", source_id: "talos", source_name: "Cisco Talos", source_kind: "rss", title: "Example campaign report", excerpt: "Source excerpt", summary: "A deterministic stored summary.", url: "https://example.test/report", published_at: new Date(Date.now() - 125_000).toISOString(), region: "global", relevance: "general", region_reasons: ["No explicit regional targeting"], topic: "research", severity: null, entities: [] };
const vuln = { id: "CVE-2026-1234", cve_id: "CVE-2026-1234", title: "Example vulnerability", description: "Stored vulnerability description", published_at: now, activity_at: now, updated_at: now, products: ["Example product"], severity: null, sources: ["NVD"], references: [], scores: [], reports: [], reported_zero_day: false, known_exploited: false };
const report = { id: "ioc-preview", vendor: "talos", title: "Example IOC report", path: "iocs.txt", source_url: "https://example.test/iocs", article_url: null, published_at: now, activity_at: now, collected_at: now, commit: "a".repeat(40), blob: "b".repeat(40), parser_version: "1", license: "CC0-1.0", license_url: "https://example.test/license", attribution: "Cisco Talos", indicator_count: 12, types: ["domain"], warnings: [], withdrawn: false };

async function mocks(page: Page) {
  const errors: string[] = []; const requests: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname; requests.push(path);
    if (path.endsWith("/threat-feed/home")) return route.fulfill({ json: { generated_at: now, summary: { regions: { global: { total: 15, recent: 15 }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, critical: 0, new_iocs: 0, source_errors: 0, last_refreshed_at: now }, sections: { global: { items: Array.from({ length: 15 }, (_, i) => ({ ...news, id: i ? `news-${i}` : news.id, title: i ? `Report ${i}` : news.title })), total: 15 }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } } } });
    if (path.endsWith("/items/news-preview")) return route.fulfill({ json: news });
    if (path.endsWith(`/vulnerabilities/${vuln.id}`)) return route.fulfill({ json: vuln });
    if (path.endsWith("/vulnerabilities")) return route.fulfill({ json: { items: [vuln], total: 1, page: 1, page_size: 20, sources: ["NVD"], published_24h: 1, zero_days_24h: 0, kev_added_24h: 0, sync_status: "current", last_synced_at: now, generated_at: now } });
    if (path.endsWith(`/ioc-reports/${report.id}`)) return route.fulfill({ json: { report, indicators: Array.from({ length: 12 }, (_, i) => ({ id: String(i), type: "domain", value: `sample${i}.test`, original: `sample${i}.test`, disposition: "source-reported", verified: false })) } });
    if (path.endsWith("/ioc-reports")) return route.fulfill({ json: { items: [report], total: 1, page: 1, page_size: 20, unique_indicators: 12, recent_indicators: 12, sources: [], generated_at: now } });
    if (path.endsWith("/status")) return route.fulfill({ json: { generated_at: now, sources: [], next_refresh_at: now } });
    return route.fulfill({ json: { status: "ok" } });
  });
  return { errors, requests };
}

for (const width of [1280, 390]) {
  test(`preview preserves scroll, traps focus and marks read at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const { errors, requests } = await mocks(page);
    await page.goto("/threat-feed");
    const button = page.getByRole("button", { name: `Preview ${news.title}`, exact: true });
    await button.scrollIntoViewIfNeeded();
    const row = button.locator("xpath=ancestor::li");
    await expect(row.locator('[aria-label="Unread"]')).toBeVisible();
    const scroll = await page.evaluate(() => scrollY);
    await button.click();
    const drawer = page.getByRole("dialog", { name: news.title });
    await expect(drawer.getByText(news.summary)).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Close preview" })).toBeFocused();
    await expect(drawer).toHaveCSS("transform", "none");
    await expect(drawer).toHaveCSS("background-color", "rgb(9, 9, 11)");
    if (width === 390) {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await expect(drawer).toHaveCSS("animation-duration", "1e-05s");
    }
    await page.keyboard.press("Shift+Tab");
    expect(await drawer.evaluate((node) => node.contains(document.activeElement))).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: `test-results/feed-preview-${width}.png` });
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0); await expect(button).toBeFocused();
    expect(await page.evaluate(() => scrollY)).toBe(scroll);
    await expect(row.locator('[aria-label="Read"]')).toBeVisible();
    await row.locator("time").focus();
    await expect(row.locator(".feed-date-tip")).toBeVisible();
    await expect(row.locator("time")).toHaveAttribute("aria-label", /GMT/);
    await page.reload(); await expect(page.getByRole("button", { name: `Preview ${news.title}`, exact: true }).locator("xpath=ancestor::li").locator('[aria-label="Read"]')).toBeVisible();
    expect(requests.some((path) => path.includes("/investigate") || path.includes("/poc/lookup"))).toBe(false);
    expect(errors).toEqual([]);
  });
}

test("column choices and spacing persist, preview distinguishes not-rated records", async ({ page }) => {
  const { errors } = await mocks(page);
  await page.goto("/threat-feed?tab=vulnerabilities");
  await expect(page.getByRole("columnheader", { name: "Affected product" })).toBeVisible();
  await page.getByText("Table display options", { exact: true }).click();
  await page.getByRole("checkbox", { name: "Affected product" }).uncheck();
  await page.getByLabel("Table spacing").selectOption("comfortable");
  await expect(page.getByRole("columnheader", { name: "Affected product" })).toHaveCount(0);
  await page.reload(); await expect(page.getByRole("columnheader", { name: "Affected product" })).toHaveCount(0);
  await page.getByText("Table display options", { exact: true }).click();
  await expect(page.getByLabel("Table spacing")).toHaveValue("comfortable");
  await page.getByRole("button", { name: `Preview ${vuln.title}` }).click();
  await expect(page.getByRole("dialog").getByText("Severity: Not rated", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Reset table display" }).click();
  await expect(page.getByRole("columnheader", { name: "Affected product" })).toBeVisible();
  expect(errors).toEqual([]);
});

test("IOC preview keeps attribution, defangs and bounds the displayed list", async ({ page }) => {
  const { errors } = await mocks(page);
  await page.goto("/threat-feed?tab=iocs");
  await page.getByRole("button", { name: `Preview ${report.title}` }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText("domain: sample0[.]test", { exact: true })).toBeVisible();
  await expect(drawer.getByText(/First 10 shown/)).toBeVisible();
  await expect(drawer.getByText("Cisco Talos · CC0-1.0", { exact: true })).toBeVisible();
  await expect(drawer.getByText("domain: sample11[.]test", { exact: true })).toHaveCount(0);
  await page.keyboard.press("Escape"); expect(errors).toEqual([]);
});

test("Saved checks a page once, retains failed coverage, and confirms safe transfer", async ({ page }) => {
  const { errors, requests } = await mocks(page);
  await page.addInitScript(() => {
    if (!localStorage.getItem("threatlens.feed.saved.v1")) localStorage.setItem("threatlens.feed.saved.v1", JSON.stringify({ version: 1, items: Array.from({ length: 20 }, (_, i) => ({ kind: "news", id: `saved-${i}`, title: `Saved ${i}`, href: `/threat-feed/saved-${i}`, saved_at: new Date().toISOString() })) }));
  });
  let count = 0;
  await page.route("**/api/v1/threat-feed/bookmarks/availability", (route) => {
    count++;
    if (count === 1) return route.fulfill({ status: 503, json: { detail: "Unavailable" } });
    const { items } = route.request().postDataJSON() as { items: { kind: string; id: string }[] };
    expect(items.length).toBeLessThanOrEqual(20);
    return route.fulfill({ json: items.map((item) => ({ ...item, available: true, title: null })) });
  });
  await page.goto("/threat-feed?view=saved");
  await expect(page.getByRole("button", { name: "Retry availability" })).toBeVisible();
  await expect(page.getByText("Unavailable or expired; bookmark retained", { exact: false })).toHaveCount(0);
  expect(count).toBe(1);
  await page.getByRole("button", { name: "Retry availability" }).click();
  await expect(page.getByRole("button", { name: "Retry availability" })).toHaveCount(0);
  expect(count).toBe(2);
  expect(requests.filter((path) => path.includes("/items/"))).toHaveLength(0);
  const download = page.waitForEvent("download"); await page.getByRole("button", { name: "Export bookmarks" }).click();
  expect((await download).suggestedFilename()).toBe("threatlens-bookmarks.json");
  const imported = { format: "threatlens-feed-bookmarks", version: 1, items: [{ kind: "news", id: "saved-0", title: "Do not replace", href: "/threat-feed/saved-0", saved_at: now }, { kind: "ioc", id: report.id, title: report.title, href: `/threat-feed/ioc-reports/${report.id}`, saved_at: now }] };
  await page.getByLabel("Import bookmarks", { exact: true }).setInputFiles({ name: "bookmarks.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(imported)) });
  await expect(page.getByText(/Import preview: 1 new · 1 duplicates/)).toBeVisible();
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("threatlens.feed.saved.v1")!).items.length)).toBe(20);
  await page.getByRole("button", { name: "Confirm bookmark import" }).click();
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("threatlens.feed.saved.v1")!).items.length)).toBe(21);
  await expect(page.getByRole("link", { name: "Saved 0", exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("Settings failures are independent and retry only the failed read", async ({ page }) => {
  const { errors } = await mocks(page);
  const user = { id: "11111111-1111-4111-8111-111111111111", aud: "authenticated", role: "authenticated", email: "test@example.test", app_metadata: {}, user_metadata: {}, created_at: now };
  const session = { access_token: "mock-access-token", refresh_token: "mock-refresh-token", expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, token_type: "bearer", user };
  await page.context().addCookies([{ name: "sb-127-auth-token", value: `base64-${Buffer.from(JSON.stringify(session)).toString("base64url")}`, url: "http://localhost:31987" }]);
  await page.route("http://127.0.0.1:54321/auth/v1/**", (route) => route.fulfill({ json: user }));
  await page.route("**/api/v1/backup/history", (route) => route.fulfill({ json: { entries: [] } }));
  await page.route("**/api/v1/threat-feed/ioc-reports/sources", (route) => route.fulfill({ json: [] }));
  let attempts = 0; let ready = false;
  await page.route("**/api/v1/threat-feed/sources", (route) => {
    attempts++; return !ready ? route.fulfill({ status: 503, json: {} }) : route.fulfill({ json: [{ id: "talos", name: "Cisco Talos", kind: "rss", enabled: true, last_success_at: now, last_error_code: null, last_error: null, last_added: 1 }] });
  });
  await mockOwnerAccess(page, user.id);
  await page.goto("/settings");
  await expect(page.getByRole("button", { name: "Retry feed source status" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Download backup", exact: true })).toBeVisible();
  const previousAttempts = attempts; ready = true;
  await page.getByRole("button", { name: "Retry feed source status" }).click();
  await expect(page.getByText("Cisco Talos", { exact: true })).toBeVisible();
  expect(attempts).toBe(previousAttempts + 1); expect(errors).toEqual([]);
});
