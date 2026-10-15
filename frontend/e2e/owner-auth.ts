import type { Page } from "@playwright/test";
export const OWNER = "00000000-0000-4000-8000-000000000001";
export async function mockOwnerAccess(page: Page, id = OWNER) {
  await page.route("**/api/v1/auth/me", (route) => route.fulfill({ json: { user_id: id, owner: true } }));
}
export async function mockOwnerSignIn(page: Page, id = OWNER) {
  const user = { id, aud: "authenticated", role: "authenticated", email: "owner@example.test", app_metadata: {}, user_metadata: {}, created_at: new Date().toISOString() };
  const session = { access_token: "mock-access-token", refresh_token: "mock-refresh-token", expires_in: 3600, expires_at: Math.floor(Date.now()/1000)+3600, token_type: "bearer", user };
  await page.context().addCookies([{ name: "sb-127-auth-token", value: `base64-${Buffer.from(JSON.stringify(session)).toString("base64url")}`, url: "http://localhost:31987" }]);
  await page.route("http://127.0.0.1:54321/auth/v1/**", (route) => route.fulfill({ json: user }));
  await mockOwnerAccess(page, id);
}
