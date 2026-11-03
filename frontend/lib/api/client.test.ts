import { afterEach, expect, it, vi } from "vitest";
import { ApiError, get, getUncached, post, PUBLIC_READ_TIMEOUT_MS } from "./client";
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

it("public feed reads omit credentials, coalesce work and isolate consumer cancellation", async () => {
  let finish!: (value: Response) => void;
  let upstream: AbortSignal | undefined;
  const fetch = vi.fn((_url: string, init: RequestInit) => { upstream = init.signal!; return new Promise<Response>((resolve) => { finish = resolve; }); });
  vi.stubGlobal("fetch", fetch);
  const caller = new AbortController();
  const first = get("/threat-feed/home?test=coalesce", caller.signal);
  const second = get("/threat-feed/home?test=coalesce");
  caller.abort(); await expect(first).rejects.toMatchObject({ name: "AbortError" });
  expect(upstream?.aborted).toBe(false);
  finish(new Response(JSON.stringify({ count: 2 })));
  await expect(second).resolves.toEqual({ count: 2 });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0][1].credentials).toBe("omit");
  expect(new Headers(fetch.mock.calls[0][1].headers).has("Authorization")).toBe(false);
});

it("bounds a stalled public response without retrying and releases the request key", async () => {
  vi.useFakeTimers();
  const fetch = vi.fn(() => new Promise<Response>(() => undefined)); vi.stubGlobal("fetch", fetch);
  const pending = get("/threat-feed/home?test=deadline");
  const assertion = expect(pending).rejects.toMatchObject({ status: 408, errorCode: "timeout" });
  await vi.advanceTimersByTimeAsync(PUBLIC_READ_TIMEOUT_MS); await assertion;
  expect(fetch).toHaveBeenCalledTimes(1);
  fetch.mockImplementationOnce(() => Promise.resolve(new Response("{}")));
  await expect(get("/threat-feed/home?test=deadline")).resolves.toEqual({});
});

it("fresh reads never join ordinary reads and aborting all consumers stops upstream", async () => {
  const signals: AbortSignal[] = [];
  vi.stubGlobal("fetch", vi.fn((_url, init) => new Promise((_resolve, reject) => {
    signals.push(init.signal); init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
  })));
  const normal = new AbortController(), fresh = new AbortController();
  const a = get("/threat-feed/home?test=cancel", normal.signal), b = getUncached("/threat-feed/home?test=cancel", fresh.signal);
  normal.abort(); fresh.abort();
  await Promise.all([expect(a).rejects.toMatchObject({ name: "AbortError" }), expect(b).rejects.toMatchObject({ name: "AbortError" })]);
  expect(signals).toHaveLength(2); expect(signals.every((s) => s.aborted)).toBe(true);
});

it("reuses a read when an effect immediately cancels and resubscribes", async () => {
  let finish!: (response: Response) => void;
  const fetch = vi.fn(() => new Promise<Response>((resolve) => { finish = resolve; })); vi.stubGlobal("fetch", fetch);
  const controller = new AbortController();
  const first = get("/threat-feed/home?test=resubscribe", controller.signal);
  controller.abort();
  const replacement = get("/threat-feed/home?test=resubscribe");
  await expect(first).rejects.toMatchObject({ name: "AbortError" });
  finish(new Response("{}")); await expect(replacement).resolves.toEqual({});
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("also aborts a stalled response body after headers have arrived", async () => {
  vi.useFakeTimers(); let bodySignal: AbortSignal | undefined;
  vi.stubGlobal("fetch", vi.fn((_url, init) => {
    bodySignal = init.signal;
    return Promise.resolve({ ok: true, status: 200, json: () => new Promise(() => undefined) });
  }));
  const pending = get("/threat-feed/home?test=body");
  const assertion = expect(pending).rejects.toMatchObject({ status: 408 });
  await vi.advanceTimersByTimeAsync(PUBLIC_READ_TIMEOUT_MS); await assertion;
  expect(bodySignal?.aborted).toBe(true);
});
