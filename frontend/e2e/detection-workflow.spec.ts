import { expect, test } from "@playwright/test";

const investigation: Record<string, any> = {
  id: "11111111-1111-4111-8111-111111111111",
  title: "Domain: example.test",
  summary: "Fixture investigation",
  status: "open",
  severity: 3,
  investigation_type: "domain",
  tags: [], metadata: {}, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
  investigation_summary: null, correlation_summary: null,
  detection_package: {
    id: "pkg_fixture",
    metadata: { engine_version: "1.0", source_engine_version: "1.0", entity_type: "domain", entity_value: "example.test", generated_at: "2026-01-01T00:00:00Z", source_finding_count: 1, source_posture: 3 },
    artifacts: [{ id: "det_fixture", language: "sigma", target: { language: "sigma", platform: "generic", product: null }, title: "Malicious domain: example.test", description: "Fixture", content: "title: Fixture\nlogsource: {category: dns}\ndetection: {selection: {query: example.test}, condition: selection}", severity: 3, category: "dns", capabilities: ["ioc_match"], source_finding_ids: ["f1"], references: [], validation: { status: "valid", validator: "threatlens.structural", level: "structural", messages: [] }, review_status: "draft", review_note: "", reviewed_at: null, reviewed_by: null, rule_id: "rule_fixture", metadata: { mapping_profile: "generic", mapping_version: "1" } }],
    languages: ["sigma"], references: [], source_finding_ids: ["f1"], generation_issues: [],
  },
};

test.beforeEach(async ({ page }) => {
  await page.route(/\/api\/v1\/workspace(?:\/|$|\?)/, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith(`/${investigation.id}`)) {
      await route.fulfill({ json: investigation });
      return;
    }
    await route.fulfill({
      json: {
        investigations: [{
          id: investigation.id, title: investigation.title, summary: investigation.summary,
          status: investigation.status, severity: investigation.severity,
          investigation_type: investigation.investigation_type, tags: [],
          created_at: investigation.created_at, updated_at: investigation.updated_at,
        }],
        total: 1,
      },
    });
  });
});

test("opens a saved IOC, reviews its generated rule, and exposes export", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
  await page.goto("/detections");
  await expect(page.getByRole("heading", { name: "Detection Workspace" })).toBeVisible();
  const iocTitles = page.getByText("Malicious domain: example.test");
  await expect(iocTitles.first()).toBeVisible();
  await iocTitles.nth(1).click();
  await expect(page.getByRole("button", { name: /download/i })).toBeVisible();
});

test("shows partial generation warnings", async ({ page }) => {
  investigation.detection_package.generation_issues = [{ generator: "yara", language: "yara", error_category: "RuntimeError", message: "Generator failed", affected_finding_ids: ["f1"] }];
  await page.goto("/detections");
  await expect(page.getByText(/Some detection formats failed/)).toBeVisible();
});
