import { expect, test, type Page } from "@playwright/test";

function entity(value: string, type = "domain") {
  return { type, value, normalized_value: value, confidence: 100, validation: "valid", possible_matches: [], routing: { providers: [] } };
}

function investigation(value: string, type = "domain") {
  const item = entity(value, type);
  const aggregate = { entity_type: type, entity_value: value, providers: [], evidence: [], relationships: [], references: [], tags: [], metadata: {}, agreement: { malicious: 0, suspicious: 0, benign: 0, unknown: 0, no_data: 0, failures: 0, conflicted: false } };
  return { investigation_id: `inv-${value}`, entity: item, threat_intelligence: aggregate, knowledge: aggregate, investigation_summary: { entity_type: type, entity_value: value, posture: 1, overall_confidence: { score: 50, band: "moderate", contested: false, factors: [] }, categories: [], findings: [], recommendations: [], engine_version: "1", generated_at: "2026-01-01T00:00:00Z" }, exposure: null, correlation: null, identity: null };
}

async function mockPreview(page: Page, values: string[]) {
  await page.route("**/api/v1/investigate/batch/preview", (route) => route.fulfill({ json: { entities: values.map((value) => entity(value)), supported: values.length, duplicates: 1, invalid: 1, estimated_ti_requests: values.length * 2, requires_confirmation: values.length >= 6, quota_warning: values.length >= 6 ? "Large batches may consume free-provider quotas." : null, single_entity: null } }));
}

test("confirms a large batch before any investigation starts", async ({ page }) => {
  const values = Array.from({ length: 6 }, (_, index) => `ioc-${index}.com`);
  await mockPreview(page, values);
  let investigationCalls = 0;
  await page.route("**/api/v1/investigate", (route) => { investigationCalls += 1; return route.fulfill({ json: investigation("unused.com") }); });
  await page.goto("/");
  await page.getByLabel("Search one or more IOCs").fill(values.join(" "));
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByRole("heading", { name: "Confirm batch investigation" })).toBeVisible();
  await expect(page.getByText(/6 indicators found.*1 duplicates removed.*1 invalid/)).toBeVisible();
  expect(investigationCalls).toBe(0);
});

test("runs, retries, saves and exports selected batch rows", async ({ page }) => {
  await mockPreview(page, ["good.com", "retry.com"]);
  let retryCalls = 0;
  await page.route("**/api/v1/investigate", async (route) => {
    const value = JSON.parse(route.request().postData() ?? "{}").query as string;
    if (value === "retry.com" && retryCalls++ === 0) return route.fulfill({ status: 503, json: {} });
    return route.fulfill({ json: investigation(value) });
  });
  let saves = 0;
  await page.route("**/api/v1/workspace", async (route) => {
    saves += 1;
    const body = JSON.parse(route.request().postData() ?? "{}");
    return route.fulfill({ json: { id: `saved-${saves}`, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", status: "open", tags: [], summary: null, severity: null, detection_package: null, correlation_summary: null, ...body } });
  });
  await page.goto("/");
  await page.getByLabel("Search one or more IOCs").fill("good.com retry.com");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByText(/1 of 2 completed.*1 failed/)).toBeVisible();
  await page.getByRole("button", { name: "Retry failed" }).click();
  await expect(page.getByText(/2 of 2 completed/)).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON" }).click();
  expect((await download).suggestedFilename()).toBe("threatlens-batch.json");
  await page.getByRole("button", { name: "Save selected" }).click();
  await expect(page.getByText(/2 added, 0 already saved, 0 failed/)).toBeVisible();
  expect(saves).toBe(2);
});
