import { expect, test, type Page } from "@playwright/test";

const cve = "CVE-2021-44228";
const resource = { source: "metasploit", id: "example", path: "modules/exploits/multi/example.rb", name: "Example official module", kind: "exploit", module_type: "exploit", description: "Source metadata only", cves: [cve], platforms: ["linux"], disclosure_date: null, modified_at: null, check_supported: true, severity: null, url: "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/example.rb", verification: "cve_reference_confirmed", locally_tested: false };
const result = { source: "metasploit", cve, status: "completed", matches: [resource], total_matches: 1, truncated: false, checked_at: new Date().toISOString(), cached: false, cache_age_seconds: 0, stale: false, error_code: null, message: "CVE reference confirmed; resources are not locally tested.", retryable: false, next_eligible_at: null, skipped_records: 0 };

async function signIn(page: Page) {
  const user = { id: "00000000-0000-4000-8000-000000000001", aud: "authenticated", role: "authenticated", email: "test@example.test", app_metadata: {}, user_metadata: {}, created_at: new Date().toISOString() };
  const session = { access_token: "mock-access-token", refresh_token: "mock-refresh-token", expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, token_type: "bearer", user };
  await page.context().addCookies([{ name: "sb-127-auth-token", value: `base64-${Buffer.from(JSON.stringify(session)).toString("base64url")}`, url: "http://localhost:31987" }]);
  await page.route("http://127.0.0.1:54321/auth/v1/**", (route) => route.fulfill({ json: user }));
}

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", (route) => route.fulfill({ json: { status: "ok" } }));
});

test("signed-out tab is public and performs no online lookups", async ({ page }) => {
  let requests = 0;
  await page.route("**/api/v1/poc/**", (route) => { requests++; return route.abort(); });
  await page.goto(`/threat-feed?tab=poc&cve=${cve}`);
  await expect(page.getByRole("link", { name: "Sign in for PoC lookup" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Search", exact: true })).toHaveCount(0);
  expect(requests).toBe(0);
});

test("progressive source results, manual retry, filters and no persistent history", async ({ page }) => {
  await signIn(page);
  let nucleiCalls = 0;
  let calls = 0;
  await page.route("**/api/v1/poc/lookup/*", async (route) => {
    calls++;
    expect(route.request().headers().authorization).toBe("Bearer mock-access-token");
    if (route.request().url().endsWith("nuclei")) {
      nucleiCalls++;
      await new Promise((resolve) => setTimeout(resolve, 600));
      return route.fulfill({ json: nucleiCalls === 1 ? { ...result, source: "nuclei", status: "timed_out", matches: [], message: "Source lookup timed out.", retryable: true } : { ...result, source: "nuclei", matches: [{ ...resource, source: "nuclei", id: "template", name: "Example official template", kind: "detection", module_type: null, check_supported: null }] } });
    }
    return route.fulfill({ json: result });
  });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`/threat-feed?tab=poc&cve=${cve}`);
  await expect(page.getByRole("textbox", { name: "CVE identifier" })).toHaveValue(cve);
  expect(calls).toBe(0);
  await page.getByRole("textbox", { name: "CVE identifier" }).fill("cve-2021-44228");
  expect(calls).toBe(0);
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page.getByRole("link", { name: "Example official module" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Nuclei source status" }).getByText("Checking…")).toBeVisible();
  await page.getByRole("button", { name: "Retry Nuclei" }).click();
  await expect(page.getByRole("link", { name: "Example official template" })).toBeVisible();
  await page.getByRole("combobox", { name: "PoC tool filter" }).selectOption("nuclei");
  await expect(page).toHaveURL(/tool=nuclei/);
  await expect(page.getByRole("link", { name: "Example official module" })).toHaveCount(0);
  await expect(page.getByText("Not locally tested", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(localStorage).filter((key) => /poc/i.test(key)))).toEqual([]);
  expect(errors).toEqual([]);
  await page.reload();
  await expect(page.getByRole("combobox", { name: "PoC tool filter" })).toHaveCount(0);
  expect(calls).toBe(3);
});

test("new searches reject late responses and mobile layout does not overflow", async ({ page }) => {
  await signIn(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/v1/poc/lookup/*", async (route) => {
    const body = route.request().postDataJSON();
    const old = body.cve === cve;
    if (old) await new Promise((resolve) => setTimeout(resolve, 800));
    const source = route.request().url().endsWith("nuclei") ? "nuclei" : "metasploit";
    await route.fulfill({ json: { ...result, source, cve: body.cve, matches: [{ ...resource, source, name: old ? "Old result" : "Latest result" }] } }).catch(() => undefined);
  });
  await page.goto(`/threat-feed?tab=poc&cve=${cve}`);
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await page.getByRole("textbox", { name: "CVE identifier" }).fill("CVE-2022-12345");
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page.getByRole("link", { name: "Latest result" }).first()).toBeVisible();
  await expect(page.getByRole("link", { name: "Old result" })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  if (process.env.THREATLENS_VISUAL_CHECK === "1") await page.screenshot({ path: "test-results/poc-mobile.png", fullPage: true });
});
