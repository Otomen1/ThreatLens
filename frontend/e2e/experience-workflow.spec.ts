import { expect, test, type Page } from "@playwright/test";

const id = "11111111-1111-4111-8111-111111111111";
function snapshot(value = "example.test") {
  const aggregate = { entity_type: "domain", entity_value: value, providers: [], evidence: [], relationships: [], references: [], tags: [], metadata: {}, agreement: { malicious: 0, suspicious: 0, benign: 0, unknown: 0, no_data: 0, failures: 0, conflicted: false } };
  const confidence = { score: 54, band: "moderate", contested: false, factors: [] };
  return { investigation_id: `inv-${value}`, entity: { type: "domain", value, normalized_value: value, confidence: 100, validation: "valid", possible_matches: [], routing: { providers: [] } }, threat_intelligence: aggregate, knowledge: aggregate, investigation_summary: { entity_type: "domain", entity_value: value, posture: 3, overall_confidence: confidence, categories: [], findings: [{ id: "f1", title: `Reported malicious infrastructure: ${value}`, categories: [], subject_type: "domain", subject_value: value, severity: 3, confidence, priority: 120, evidence: [], relationships: [], sources: [], rationale: "Fixture", rule_ids: [], recommendations: [] }], recommendations: [], engine_version: "1", generated_at: "2026-01-01T00:00:00Z" }, exposure: null, correlation: null, identity: null };
}
const pkg = { id: "pkg_fixture", metadata: { engine_version: "1", source_engine_version: "1", entity_type: "domain", entity_value: "example.test", generated_at: "2026-01-01T00:00:00Z", source_finding_count: 1, source_posture: 3 }, artifacts: [{ id: "det_fixture", language: "sigma", target: { language: "sigma", platform: "generic", product: null }, title: "Malicious domain: example.test", description: "Fixture", content: "title: Fixture\nlogsource: {category: dns}\ndetection: {selection: {query: example.test}, condition: selection}", severity: 3, category: "dns", capabilities: ["ioc_match"], source_finding_ids: ["f1"], references: [], validation: { status: "valid", validator: "threatlens.structural", level: "structural", messages: [] }, review_status: "draft", review_note: "", reviewed_at: null, reviewed_by: null, rule_id: "rule_fixture", metadata: { mapping_profile: "generic", mapping_version: "1" } }], languages: ["sigma"], references: [], source_finding_ids: ["f1"], generation_issues: [] };

async function signIn(page: Page) {
  const user = { id, aud: "authenticated", role: "authenticated", email: "test@example.test", app_metadata: {}, user_metadata: {}, created_at: new Date().toISOString() };
  const session = { access_token: "mock-access-token", refresh_token: "mock-refresh-token", expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, token_type: "bearer", user };
  await page.context().addCookies([{ name: "sb-127-auth-token", value: `base64-${Buffer.from(JSON.stringify(session)).toString("base64url")}`, url: "http://localhost:31987" }]);
  await page.route("http://127.0.0.1:54321/auth/v1/**", (route) => route.fulfill({ json: user }));
}
test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", (route) => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/api/v1/backup/history", (route) => route.fulfill({ json: { entries: [] } }));
  await page.route("**/api/v1/threat-feed/sources", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/v1/threat-feed/home?*", (route) => route.fulfill({ json: { sections: { global: { items: [], total: 0 }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } } } }));
  await page.route("**/api/v1/workspace/start-summary", (route) => route.fulfill({ json: { recent: [], investigations: 0, draft_detections: 0, open_cases: 0, provider_issues: [], availability: { workspace: true, cases: true, providers: true } } }));
  await page.route("**/api/v1/investigate/batch/preview", (route) => { const value = route.request().postDataJSON().query; return route.fulfill({ json: { entities: [snapshot(value).entity], supported: 1, duplicates: 0, invalid: 0, estimated_ti_requests: 1, requires_confirmation: false } }); });
  await page.route("**/api/v1/investigate", (route) => route.fulfill({ json: snapshot(route.request().postDataJSON().query) }));
});
async function search(page: Page, value = "example.test") { await page.getByLabel("Search one or more IOCs").fill(value); await page.getByRole("button", { name: "Search", exact: true }).click(); }

test("save, generate, failed rule save, retry, review and export without regenerating", async ({ page }) => {
  await signIn(page);
  let generations = 0; let creates = 0; let updates = 0;
  let record: Record<string, unknown> = { id, title: "Domain: example.test", status: "open", tags: [], metadata: {}, investigation_type: "domain", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", detection_package: null, investigation_summary: snapshot().investigation_summary, investigation_snapshot: snapshot(), correlation_summary: null };
  await page.route("**/api/v1/detections", (route) => { generations++; return route.fulfill({ json: pkg }); });
  await page.route("**/api/v1/workspace", (route) => { if (route.request().method() === "POST") { creates++; record = { ...record, ...route.request().postDataJSON() }; return route.fulfill({ json: record }); } return route.fulfill({ json: { investigations: [record], total: 1 } }); });
  await page.route(`**/api/v1/workspace/${id}`, (route) => { if (route.request().method() === "PUT") { updates++; if (updates === 1) return route.fulfill({ status: 503, json: {} }); record = { ...record, ...route.request().postDataJSON() }; } return route.fulfill({ json: record }); });
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/"); await search(page);
  const workflow = page.getByRole("region", { name: "Investigation workflow" });
  await workflow.getByRole("button", { name: "Save to Workspace" }).click();
  await expect(workflow.getByRole("link", { name: /View in Workspace/ })).toBeVisible();
  await workflow.getByRole("button", { name: "Generate detections" }).click();
  await workflow.getByRole("button", { name: "Save rules to this investigation" }).click();
  await expect(workflow.getByRole("alert")).toContainText("generated package remains available");
  await workflow.getByRole("button", { name: "Save rules to this investigation" }).click();
  await expect(workflow.getByRole("link", { name: "Review rules" })).toBeVisible();
  expect(generations).toBe(1); expect(creates).toBe(1);
  const packageDownload = page.waitForEvent("download"); await workflow.getByRole("button", { name: "Export rules" }).click(); expect((await packageDownload).suggestedFilename()).toBe("threatlens-detection-package.json");
  await workflow.getByRole("link", { name: "Review rules" }).click();
  await expect(page).toHaveURL(new RegExp(`investigation=${id}`));
  await page.getByText("Malicious domain: example.test", { exact: true }).first().click();
  await page.getByText("Malicious domain: example.test", { exact: true }).nth(1).click();
  await page.getByRole("button", { name: "Mark reviewed" }).click();
  await expect(page.getByText("generic v1 · structural · reviewed")).toBeVisible();
  const download = page.waitForEvent("download"); await page.getByRole("button", { name: "Download", exact: true }).click(); expect((await download).suggestedFilename()).toMatch(/\.yml$/);
  expect(errors).toEqual([]);
});

test("failed refresh and cancelled later search preserve the previous entity", async ({ page }) => {
  await page.goto("/"); await search(page);
  await expect(page.getByRole("region", { name: "Result overview" })).toContainText("example.test");
  await page.route("**/api/v1/investigate", (route) => route.fulfill({ status: 503, json: { error_code: "upstream_error", retryable: true, error: "secret payload" } }));
  await page.getByRole("button", { name: "Refresh now" }).click();
  await expect(page.getByText("Previous result: example.test.", { exact: false })).toBeVisible();
  await expect(page.getByRole("region", { name: "Result overview" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry", exact: true })).toBeVisible();
  await expect(page.getByText("secret payload")).toHaveCount(0);
  await page.route("**/api/v1/investigate", async (route) => { await new Promise((resolve) => setTimeout(resolve, 800)); await route.fulfill({ json: snapshot("late.test") }).catch(() => undefined); });
  await search(page, "late.test"); await page.getByRole("button", { name: "Cancel investigation", exact: true }).click();
  await expect(page.getByRole("region", { name: "Result overview" })).toContainText("example.test");
  await page.waitForTimeout(1000);
  await expect(page.getByRole("region", { name: "Result overview" })).not.toContainText("late.test");
});

test("signed-out start screen has no private requests; URL overrides preferences", async ({ page }) => {
  let privateCalls = 0;
  await page.route("**/api/v1/workspace/start-summary", (route) => { privateCalls++; return route.abort(); });
  await page.addInitScript(() => localStorage.setItem("threatlens.experience.v1", JSON.stringify({ version: 1, value: { scanMode: "fast", view: "card", pageSize: 50, formats: ["yara"] } })));
  await page.goto("/?scan_mode=full");
  await expect(page.getByRole("region", { name: "Start here" })).toContainText("Sign in");
  await expect(page.getByLabel("Scan mode")).toHaveValue("full"); expect(privateCalls).toBe(0);
  await page.goto("/detections?view=compact&page_size=10&language=sigma");
  await expect(page.getByLabel("Rule view")).toHaveValue("compact"); await expect(page.getByLabel("Rules per page")).toHaveValue("10");
});

test("settings reset does not clear bookmarks or identity history", async ({ page }) => {
  await page.addInitScript(() => { localStorage.setItem("unrelated-history", "keep"); localStorage.setItem("threatlens.experience.v1", JSON.stringify({ version: 1, value: { scanMode: "full", view: "card" } })); });
  await page.goto("/settings"); await page.getByRole("button", { name: "Reset Preferences" }).click();
  await expect(page.getByLabel("Default scan")).toHaveValue("standard");
  expect(await page.evaluate(() => localStorage.getItem("unrelated-history"))).toBe("keep");
});

test("private start metadata clears on sign-out and is not browser-persisted", async ({ page }) => {
  await signIn(page);
  await page.route("**/api/v1/workspace/start-summary", (route) => route.fulfill({ json: { recent: [{ id, title: "Private recent investigation", status: "open", updated_at: "2026-01-01T00:00:00Z" }], investigations: 1, draft_detections: 2, open_cases: 3, provider_issues: [{ provider: "otx", code: "rate_limited" }], availability: { workspace: true, cases: true, providers: true } } }));
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Continue: Private recent investigation" })).toBeVisible();
  expect(await page.evaluate(() => JSON.stringify(Object.values(localStorage)))).not.toContain("Private recent investigation");
  await page.getByRole("button", { name: "Sign out", exact: true }).first().click();
  await expect(page.getByRole("link", { name: "Continue: Private recent investigation" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Start here" })).toContainText("Sign in");
});

test("generation before save includes the package and stays usable on mobile", async ({ page }) => {
  await signIn(page); await page.setViewportSize({ width: 390, height: 844 }); await page.emulateMedia({ reducedMotion: "reduce" });
  await page.route("**/api/v1/detections", (route) => route.fulfill({ json: pkg }));
  let savedPackage = false;
  await page.route("**/api/v1/workspace", (route) => { const body = route.request().postDataJSON(); savedPackage = body.detection_package.id === pkg.id; return route.fulfill({ json: { id, ...body } }); });
  await page.goto("/"); await search(page);
  const workflow = page.getByRole("region", { name: "Investigation workflow" });
  await workflow.getByRole("button", { name: "Generate detections" }).click();
  await expect(workflow.getByRole("button", { name: "Export rules" })).toBeEnabled();
  await workflow.getByRole("button", { name: "Save to Workspace" }).click();
  await expect(workflow.getByRole("link", { name: "Review rules" })).toBeVisible(); expect(savedPackage).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("server cooldown blocks retry and refresh without provider calls", async ({ page }) => {
  await page.goto("/"); await search(page);
  let attempts = 0;
  await page.route("**/api/v1/investigate", (route) => { attempts++; return route.fulfill({ status: 429, headers: { "Retry-After": "60" }, json: { error_code: "rate_limited", retryable: true } }); });
  await page.getByRole("button", { name: "Refresh now" }).click();
  await expect(page.getByText(/Retry eligible at/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh now" }).click();
  await expect(page.getByText(/Requests are cooling down until/)).toBeVisible(); expect(attempts).toBe(1);
});
