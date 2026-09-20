import { expect, test } from "@playwright/test";

test("intelligence menu remains open while moving into its dropdown", async ({ page }) => {
  await page.goto("/");

  const intelligence = page.getByRole("link", { name: "Intelligence" });
  const identity = page.getByRole("menuitem", { name: "Identity" });

  await intelligence.hover();
  await expect(identity).toBeVisible();

  await identity.hover();
  await page.waitForTimeout(500);
  await expect(identity).toBeVisible();

  await page.getByRole("main").hover({ position: { x: 20, y: 100 } });
  await expect(identity).toBeHidden();
});
