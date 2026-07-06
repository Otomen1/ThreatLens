import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  aiHealth,
  detect,
  explain,
  exposureFrameworkStatus,
  generateDetections,
  health,
  recommendCommunityDetections,
  searchCommunityDetections,
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

describe("exposureFrameworkStatus", () => {
  const STATUS_PAYLOAD = {
    status: "ready",
    message: "1 provider(s) registered",
    framework_version: "0.1.0",
    providers_registered: 1,
    providers: [
      { name: "shodan", display_name: "Shodan", status: "degraded", detail: "API key not configured" },
    ],
    summary: null,
  };

  it("GETs the exposure endpoint with no query string when no value is given", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);

    const result = await exposureFrameworkStatus();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/exposure$/);
    expect(init.method).toBe("GET");
    expect(result).toEqual(STATUS_PAYLOAD);
  });

  it("appends a URL-encoded value query param when a value is given", async () => {
    const fetchMock = stubFetch(200, { ...STATUS_PAYLOAD, summary: { entity_value: "8.8.8.8" } });

    await exposureFrameworkStatus("8.8.8.8");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/exposure\?value=8\.8\.8\.8$/);
  });

  it("URL-encodes special characters in the value", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);

    await exposureFrameworkStatus("2001:4860:4860::8888");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain(encodeURIComponent("2001:4860:4860::8888"));
  });

  it("treats a blank/whitespace value as absent", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);

    await exposureFrameworkStatus("   ");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/exposure$/);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(500, { detail: "boom" });
    await expect(exposureFrameworkStatus("8.8.8.8")).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);
    const controller = new AbortController();

    await exposureFrameworkStatus("8.8.8.8", controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
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

describe("recommendCommunityDetections", () => {
  it("POSTs the summary to the recommend endpoint and returns the matches", async () => {
    const payload = {
      entity_type: "ipv4",
      entity_value: "8.8.8.8",
      matches: [],
      exact_count: 0,
      partial_count: 0,
      related_count: 0,
      library_version: "1.0",
      sync_status: "seed",
    };
    const fetchMock = stubFetch(200, payload);

    const result = await recommendCommunityDetections(SUMMARY);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/detection-knowledge\/recommend$/);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual(SUMMARY);
    expect(result.matches).toEqual([]);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(500, { detail: "boom" });
    await expect(recommendCommunityDetections(SUMMARY)).rejects.toBeInstanceOf(ApiError);
  });
});

describe("searchCommunityDetections", () => {
  it("GETs the search endpoint with only the provided filters as query params", async () => {
    const fetchMock = stubFetch(200, { total: 0, rules: [], stats: {} });

    await searchCommunityDetections({ technique: "T1071", language: "yara", ignored: undefined });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("GET");
    expect(String(url)).toContain("/detection-knowledge/search?");
    expect(String(url)).toContain("technique=T1071");
    expect(String(url)).toContain("language=yara");
    expect(String(url)).not.toContain("ignored");
  });
});
