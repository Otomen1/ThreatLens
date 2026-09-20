import { expect, test } from "@playwright/test";

test("command menu navigates and prepares safe actions", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Control+k");
  const dialog = page.getByRole("dialog", { name: "Command menu" });
  await expect(dialog).toBeVisible();

  await dialog.getByRole("textbox", { name: "Search commands" }).fill("Start investigation");
  await dialog.getByRole("link", { name: /Start investigation/ }).click();

  await expect(page).toHaveURL(/focus=search/);
  await expect(page.getByRole("textbox", { name: "Search one or more IOCs" })).toBeFocused();
});

test("command menu closes with Escape", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeHidden();
});
