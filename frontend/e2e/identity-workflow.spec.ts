import { expect, test } from "@playwright/test";

const status = {
  status: "ready",
  message: "1 provider(s) registered",
  framework_version: "1.0.0",
  providers_registered: 1,
  enabled: true,
  providers: [{
    name: "hibp",
    display_name: "Have I Been Pwned",
    enabled: true,
    configured: true,
    status: "operational",
    detail: null,
  }],
  summary: null,
};

const emailResult = {
  cache_status: "miss",
  checked_at: "2026-09-17T12:00:00Z",
  summary: {
    entity_type: "email",
    entity_value: "analyst@example.com",
    findings: [{
      provider: "hibp",
      provider_display_name: "Have I Been Pwned",
      status: "ok",
      error: null,
      summary: "Found in 1 breach(es).",
      evidence: [{
        type: "breach",
        summary: "ExampleBreach",
        value: "Example Breach",
        observed_at: null,
        data: { breach_date: "2025-01-01", data_classes: ["Email addresses"] },
      }],
      fetched_at: "2026-09-17T12:00:00Z",
    }],
    statistics: { providers_queried: 1, providers_ok: 1, total_findings: 1, total_assets: 1, categories: ["breaches"] },
    metadata: { generated_at: "2026-09-17T12:00:00Z", framework_version: "1.0.0" },
  },
};

test.beforeEach(async ({ page }) => {
  await page.route(/\/api\/v1\/identity/, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.includes("password-range")) {
      await route.fulfill({ json: { prefix: "5BAA6", suffixes: [{ suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8", count: 42 }], checked_at: "2026-09-17T12:00:00Z" } });
    } else if (url.pathname.endsWith("email/check")) {
      await route.fulfill({ json: emailResult });
    } else {
      await route.fulfill({ json: status });
    }
  });
});

test("checks email exposure and keeps the result descriptive", async ({ page }) => {
  await page.goto("/identity");
  await page.getByLabel("Email address").fill("analyst@example.com");
  await page.getByRole("button", { name: "Check email" }).click();
  await expect(page.getByText("Example Breach")).toBeVisible();
  await expect(page.getByText("Email addresses")).toBeVisible();
  await expect(page.getByText(/not a guarantee of safety/i)).toHaveCount(0);
});

test("checks a password without sending plaintext", async ({ page }) => {
  let requestedUrl = "";
  let requestBody: string | null = null;
  page.on("request", (request) => {
    if (request.url().includes("password-range")) {
      requestedUrl = request.url();
      requestBody = request.postData();
    }
  });
  await page.goto("/identity");
  await page.getByRole("tab", { name: "Password Exposure" }).click();
  await page.getByLabel("Password to check").fill("password");
  await page.getByRole("button", { name: "Check password" }).click();
  await expect(page.getByText(/Found 42 times/)).toBeVisible();
  expect(new URL(requestedUrl).pathname).toMatch(/\/password-range\/5BAA6$/);
  expect(requestBody).toBeNull();
  await expect(page.getByLabel("Password to check")).toHaveValue("");
});
