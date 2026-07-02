import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, detect, explain, type InvestigationSummary } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function stubFetch(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response);
  vi.stubGlobal("fetch", fn);
  return fn;
}

describe("detect", () => {
  it("POSTs the query to the detect endpoint and returns the parsed result", async () => {
    const payload = { search_id: "abc", entity: { type: "ipv4" } };
    const fetchMock = stubFetch(200, payload);

    const result = await detect("8.8.8.8");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/detect$/);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ query: "8.8.8.8" });
    expect(result).toEqual(payload);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(422, { detail: "bad" });
    await expect(detect("???")).rejects.toBeInstanceOf(ApiError);
  });

  it("throws ApiError when the backend is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("network down")),
    );
    await expect(detect("x")).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, { search_id: "x", entity: {} });
    const controller = new AbortController();

    await detect("x", controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });

  it("re-throws AbortError without wrapping it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new DOMException("aborted", "AbortError")),
    );
    await expect(detect("x")).rejects.toMatchObject({ name: "AbortError" });
  });
});

const SUMMARY = {
  entity_type: "ipv4",
  entity_value: "8.8.8.8",
  posture: 3,
  findings: [],
  recommendations: [],
} as unknown as InvestigationSummary;

describe("explain", () => {
  it("POSTs the summary to the explain endpoint and returns the parsed result", async () => {
    const payload = { status: "ok", provider: "ollama", executive_summary: "bad ip" };
    const fetchMock = stubFetch(200, payload);

    const result = await explain(SUMMARY);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/explain$/);
    expect(init.method).toBe("POST");
    // The summary itself is the body — never raw provider data, never `{ query }`.
    expect(JSON.parse(init.body as string)).toEqual(SUMMARY);
    expect(result).toEqual(payload);
  });

  it.each([
    "disabled",
    "unavailable",
    "timeout",
    "invalid_response",
    "error",
  ] as const)("surfaces the %s state as a normal 200 result (never throws)", async (status) => {
    stubFetch(200, { status, provider: "ollama" });
    const result = await explain(SUMMARY);
    expect(result.status).toBe(status);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(422, { detail: "bad" });
    await expect(explain(SUMMARY)).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, { status: "disabled" });
    const controller = new AbortController();

    await explain(SUMMARY, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});
