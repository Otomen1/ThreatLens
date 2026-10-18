import { expect, test, type Page } from "@playwright/test";

const news = { id: "brief-news", source_id: "talos", source_name: "Cisco Talos", source_kind: "rss", title: "Stored news for brief", excerpt: "Compact metadata", summary: "Compact metadata", url: "https://example.test/report", published_at: new Date(Date.now() - 3600000).toISOString(), region: "global", relevance: "general", region_reasons: [], topic: "research", severity: null, entities: [] };
async function mocks(page: Page) {
  const requests: URL[] = [], errors: string[] = [];
  const state = { failed: false, delayed: false };
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url()); requests.push(url);
    if (url.pathname.endsWith("/home")) return route.fulfill({ json: { generated_at: new Date().toISOString(), summary: { regions: { global: { total: 1, recent: 1 }, malaysia: { total: 0, recent: 0 }, southeast_asia: { total: 0, recent: 0 } }, critical: 0, new_iocs: 0, source_errors: 0, last_refreshed_at: null }, sections: { global: { items: [news], total: 1 }, malaysia: { items: [], total: 0 }, southeast_asia: { items: [], total: 0 } } } });
    if (url.pathname.endsWith("/activity")) {
      if (state.delayed) await new Promise((resolve) => setTimeout(resolve, 700));
      if (state.failed) return route.fulfill({ status: 503, json: {} });
      const now = Date.now(), since = url.searchParams.get("since");
      const start = since ? Math.max(Date.parse(since), now - 30 * 86400000) : now;
      const active = Boolean(since && start < now - 3600000);
      const groups = Object.fromEntries((["news", "vulnerability", "ioc"] as const).map((kind, index) => [kind, {
        total: active ? [8, 4, 2][index] : 0,
        items: active ? [{ kind, id: `${kind}-recent`, title: `Recent ${kind}`, source: kind === "ioc" ? "talos" : "Stored source", activity_at: new Date(now - 3600000).toISOString(), href: `/threat-feed/${kind === "news" ? "" : kind === "ioc" ? "ioc-reports/" : "vulnerabilities/"}${kind}-recent` }] : [],
      }]));
      return route.fulfill({ json: { since, window_start: new Date(start).toISOString(), generated_at: new Date(now).toISOString(), limited: Boolean(since && Date.parse(since) < start), groups } });
    }
    if (url.pathname.endsWith("/status")) return route.fulfill({ json: { generated_at: new Date().toISOString(), sources: [], next_refresh_at: null } });
    return route.fulfill({ json: {} });
  });
  return { requests, errors, state };
}

test("first visit establishes a baseline without inventing activity or storing feed data", async ({ page }) => {
  const { requests, errors } = await mocks(page);
  await page.goto("/threat-feed");
  const brief = page.getByRole("region", { name: "Since your last visit" });
  await expect(brief.getByRole("status")).toHaveText(/First visit: your baseline is ready/);
  await expect(brief.getByLabel("News published: 0", { exact: true })).toHaveCount(0);
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("threatlens.feed.visit.v1")!));
  expect(Object.keys(saved)).toEqual(["version", "checked_at"]);
  expect(requests.find((url) => url.pathname.endsWith("/activity"))?.searchParams.has("since")).toBe(false);
  expect(requests.some((url) => /investigate|poc\/lookup|refresh/.test(url.pathname))).toBe(false);
  expect(errors).toEqual([]);
});

test("returning brief preserves its baseline through filtering and reload, with exact detail links", async ({ page }) => {
  const { requests, errors } = await mocks(page);
  const previous = new Date(Date.now() - 2 * 86400000).toISOString();
  await page.addInitScript((checked_at) => { if (!localStorage.getItem("threatlens.feed.visit.v1")) localStorage.setItem("threatlens.feed.visit.v1", JSON.stringify({ version: 1, checked_at })); }, previous);
  await page.goto("/threat-feed");
  const brief = page.getByRole("region", { name: "Since your last visit" });
  await expect(brief.getByLabel("News published: 8", { exact: true })).toBeVisible();
  await expect(brief.getByLabel("Vulnerability activity: 4", { exact: true })).toBeVisible();
  await brief.getByText("Brief details", { exact: true }).click();
  await expect(brief.getByRole("link", { name: "Recent vulnerability", exact: true })).toHaveAttribute("href", "/threat-feed/vulnerabilities/vulnerability-recent");
  await page.getByLabel("Topic", { exact: true }).selectOption("malware");
  await expect(page).toHaveURL(/topic=malware/);
  await expect(brief.getByLabel("News published: 8", { exact: true })).toBeVisible();
  await page.reload();
  await expect(brief.getByLabel("News published: 8", { exact: true })).toBeVisible();
  await brief.getByText("Brief details", { exact: true }).click();
  expect(requests.filter((url) => url.pathname.endsWith("/activity")).every((url) => url.searchParams.get("since") === previous)).toBe(true);
  await brief.getByRole("button", { name: "Mark caught up", exact: true }).click();
  await expect(brief.getByRole("status")).toHaveText(/Caught up as of the checked time/);
  await expect(brief.getByLabel("News published: 0", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("threatlens.feed.read.v1"))).toBeNull();
  expect(errors).toEqual([]);
});

test("failed brief update keeps counts and the successful checkpoint without blocking news", async ({ page }) => {
  const { requests, errors, state } = await mocks(page);
  await page.addInitScript(() => localStorage.setItem("threatlens.feed.visit.v1", JSON.stringify({ version: 1, checked_at: new Date(Date.now() - 86400000).toISOString() })));
  await page.goto("/threat-feed");
  const brief = page.getByRole("region", { name: "Since your last visit" });
  await expect(brief.getByLabel("News published: 8", { exact: true })).toBeVisible();
  const checkpoint = await page.evaluate(() => localStorage.getItem("threatlens.feed.visit.v1"));
  state.failed = true;
  await brief.getByText("Brief details", { exact: true }).click();
  await brief.getByRole("button", { name: "Check for updates", exact: true }).click();
  await expect(brief.getByRole("status")).toHaveText(/Previous brief retained.*baseline has not advanced/);
  await expect(brief.getByLabel("News published: 8", { exact: true })).toBeVisible();
  await expect(page.getByRole("table", { name: "Latest 10 news" })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("threatlens.feed.visit.v1"))).toBe(checkpoint);
  state.failed = false;
  await brief.getByRole("button", { name: "Retry activity brief", exact: true }).click();
  await expect(brief.getByRole("status")).not.toHaveText(/could not load/);
  expect(requests.filter((url) => url.pathname.endsWith("/home"))).toHaveLength(1);
  expect(errors).toEqual([]);
});

test("mobile brief discloses retention and blocked storage; obsolete responses cannot write", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const { errors, state } = await mocks(page);
  await page.addInitScript(() => {
    if (!localStorage.getItem("threatlens.feed.visit.v1")) localStorage.setItem("threatlens.feed.visit.v1", JSON.stringify({ version: 1, checked_at: new Date(Date.now() - 60 * 86400000).toISOString() }));
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) { if (key.startsWith("threatlens.feed.visit")) throw new Error("Blocked"); return original.call(this, key, value); };
  });
  await page.goto("/threat-feed");
  const brief = page.getByRole("region", { name: "Since your last visit" });
  await expect(brief.getByText(/Only the latest 30 days are included/)).toBeVisible();
  await expect(brief.getByText(/Visit history could not be saved/)).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const before = await page.evaluate(() => localStorage.getItem("threatlens.feed.visit.v1"));
  state.delayed = true;
  await brief.getByText("Brief details", { exact: true }).click();
  await brief.getByRole("button", { name: "Check for updates", exact: true }).click();
  await page.goto("/");
  expect(await page.evaluate(() => localStorage.getItem("threatlens.feed.visit.v1"))).toBe(before);
  expect(errors).toEqual([]);
});
