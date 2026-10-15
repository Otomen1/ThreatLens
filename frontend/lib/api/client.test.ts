import { afterEach, expect, it, vi } from "vitest";
import { ApiError, post } from "./client";
import { setPrivateOwner } from "../privateSession";
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); setPrivateOwner(null); });
it("uses safe errors, retryability and cooldown without exposing payloads or retrying", async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error_code: "rate_limited", retryable: false, error: "SECRET", detail: "private payload" }), { status: 429, headers: { "Retry-After": "60" } }));
  vi.stubGlobal("fetch", fetch);
  try { await post("/investigate", { query: "example.test" }); throw new Error("Expected failure"); }
  catch (error) { expect(error).toBeInstanceOf(ApiError); const safe = error as ApiError; expect(safe.errorCode).toBe("rate_limited"); expect(safe.retryable).toBe(false); expect(safe.retryAt).toBe(Date.now() + 60000); expect(safe.message).not.toMatch(/SECRET|payload/); }
  expect(fetch).toHaveBeenCalledTimes(1);
});
it("combines caller cancellation and account-change cancellation", async () => {
  const caller = new AbortController(); let captured: AbortSignal | null = null;
  vi.stubGlobal("fetch", vi.fn((_url, init) => new Promise((_resolve, reject) => {
    captured = init.signal;
    init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
  })));
  const pending = post("/investigate", {}, caller.signal);
  await vi.waitFor(() => expect(captured).not.toBeNull());
  caller.abort(); await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  setPrivateOwner("00000000-0000-4000-8000-000000000001");
  captured = null; const changed = post("/investigate", {});
  await vi.waitFor(() => expect(captured).not.toBeNull());
  setPrivateOwner(null); await expect(changed).rejects.toMatchObject({ name: "AbortError" });
});
it("rejects arbitrary upstream error codes and handles malformed error JSON", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error_code: "secret-code" }), { status: 503 })));
  await expect(post("/investigate", {})).rejects.toMatchObject({ errorCode: undefined, retryable: true });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("malformed", { status: 401 })));
  await expect(post("/investigate", {})).rejects.toMatchObject({ message: "Please sign in again.", retryable: false });
});
