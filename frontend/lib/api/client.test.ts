import { afterEach, expect, it, vi } from "vitest";
import { ApiError, post } from "./client";
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
it("uses safe errors, retryability and cooldown without exposing payloads or retrying", async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error_code: "rate_limited", retryable: false, error: "SECRET", detail: "private payload" }), { status: 429, headers: { "Retry-After": "60" } }));
  vi.stubGlobal("fetch", fetch);
  try { await post("/investigate", { query: "example.test" }); throw new Error("Expected failure"); }
  catch (error) { expect(error).toBeInstanceOf(ApiError); const safe = error as ApiError; expect(safe.errorCode).toBe("rate_limited"); expect(safe.retryable).toBe(false); expect(safe.retryAt).toBe(Date.now() + 60000); expect(safe.message).not.toMatch(/SECRET|payload/); }
  expect(fetch).toHaveBeenCalledTimes(1);
});
it("rejects arbitrary upstream error codes and handles malformed error JSON", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error_code: "secret-code" }), { status: 503 })));
  await expect(post("/investigate", {})).rejects.toMatchObject({ errorCode: undefined, retryable: true });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("malformed", { status: 401 })));
  await expect(post("/investigate", {})).rejects.toMatchObject({ message: "Please sign in again.", retryable: false });
});
