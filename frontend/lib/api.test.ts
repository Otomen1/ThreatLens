import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  aiHealth,
  detect,
  explain,
  generateDetections,
  health,
  type InvestigationSummary,
} from "./api";

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

describe("health", () => {
  it("GETs the health endpoint and returns the parsed status", async () => {
    const payload = { status: "ok", service: "threatlens", version: "1.0.0" };
    const fetchMock = stubFetch(200, payload);

    const result = await health();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/health$/);
    expect(init.method).toBe("GET");
    expect(result).toEqual(payload);
  });

  it("throws ApiError when the backend is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("down")));
    await expect(health()).rejects.toBeInstanceOf(ApiError);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(503, { ready: false });
    await expect(health()).rejects.toBeInstanceOf(ApiError);
  });
});

describe("aiHealth", () => {
  it("GETs the AI health endpoint and returns the parsed status", async () => {
    const payload = { status: "disabled", enabled: false, reachable: false };
    const fetchMock = stubFetch(200, payload);

    const result = await aiHealth();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/health\/ai$/);
    expect(init.method).toBe("GET");
    expect(result.status).toBe("disabled");
  });
});

describe("generateDetections", () => {
  it("POSTs the summary to the detections endpoint and returns the package", async () => {
    const payload = { id: "pkg_abc", artifacts: [], languages: [], source_finding_ids: [] };
    const fetchMock = stubFetch(200, payload);

    const result = await generateDetections(SUMMARY);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/detections$/);
    expect(init.method).toBe("POST");
    // The summary itself is the body — never raw provider data, never `{ query }`.
    expect(JSON.parse(init.body as string)).toEqual(SUMMARY);
    expect(result).toEqual(payload);
  });

  it("returns an empty (artifact-free) package in this phase", async () => {
    stubFetch(200, { id: "pkg_abc", artifacts: [], languages: [], source_finding_ids: ["fnd_1"] });
    const result = await generateDetections(SUMMARY);
    expect(result.artifacts).toEqual([]);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(422, { detail: "bad" });
    await expect(generateDetections(SUMMARY)).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, { id: "pkg_x", artifacts: [] });
    const controller = new AbortController();

    await generateDetections(SUMMARY, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});
