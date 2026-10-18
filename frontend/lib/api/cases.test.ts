import { afterEach, expect, it, vi } from "vitest";
import { attachFeedToCase, removeFeedFromCase } from "./cases";
import { setPrivateOwner } from "../privateSession";

afterEach(() => { vi.unstubAllGlobals(); setPrivateOwner(null); });

it("sends only a source key through private Case routes, never client provenance", async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ id: "case" }))));
  vi.stubGlobal("fetch", fetch);
  await attachFeedToCase("case", "vulnerability", "CVE-2026-1234");
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/cases/case/feed");
  expect(fetch.mock.calls[0][1].method).toBe("POST");
  expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ kind: "vulnerability", id: "CVE-2026-1234" });
  await removeFeedFromCase("case", "news", "news-id");
  expect(fetch.mock.calls[1][0]).toBe("/api/v1/cases/case/feed/news/news-id");
  expect(fetch.mock.calls[1][1].method).toBe("DELETE");
});

it("aborts pending attachments on sign-out instead of delivering private results", async () => {
  setPrivateOwner("owner");
  let signal: AbortSignal | null = null;
  vi.stubGlobal("fetch", vi.fn((_url, init) => new Promise((_resolve, reject) => {
    signal = init.signal;
    init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
  })));
  const pending = attachFeedToCase("case", "news", "news");
  await vi.waitFor(() => expect(signal).not.toBeNull());
  setPrivateOwner(null);
  await expect(pending).rejects.toMatchObject({ name: "AbortError" });
});
