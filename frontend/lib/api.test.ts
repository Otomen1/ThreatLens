import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  addCaseNote,
  aiHealth,
  correlationFrameworkStatus,
  createCase,
  deleteCase,
  deleteInvestigation,
  detect,
  explain,
  exposureFrameworkStatus,
  generateDetections,
  getCase,
  getInvestigation,
  getInvestigationGraph,
  getInvestigationReport,
  getInvestigationTimeline,
  health,
  identityFrameworkStatus,
  linkWorkspaceToCase,
  listCases,
  listInvestigations,
  recommendCommunityDetections,
  saveInvestigation,
  searchCommunityDetections,
  unlinkWorkspaceFromCase,
  updateCase,
  updateInvestigation,
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

describe("identityFrameworkStatus", () => {
  const STATUS_PAYLOAD = {
    status: "ready",
    message: "No providers configured",
    framework_version: "0.1.0",
    providers_registered: 0,
  };

  it("GETs the identity endpoint and returns the framework status", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);

    const result = await identityFrameworkStatus();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/identity$/);
    expect(init.method).toBe("GET");
    expect(result).toEqual(STATUS_PAYLOAD);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(500, { detail: "boom" });
    await expect(identityFrameworkStatus()).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);
    const controller = new AbortController();

    await identityFrameworkStatus(controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("correlationFrameworkStatus", () => {
  const STATUS_PAYLOAD = {
    status: "ready",
    message: "12 correlation rule(s) registered",
    framework_version: "0.1.0",
    rules_registered: 12,
  };

  it("GETs the correlation endpoint and returns the framework status", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);

    const result = await correlationFrameworkStatus();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/correlation$/);
    expect(init.method).toBe("GET");
    expect(result).toEqual(STATUS_PAYLOAD);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(500, { detail: "boom" });
    await expect(correlationFrameworkStatus()).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, STATUS_PAYLOAD);
    const controller = new AbortController();

    await correlationFrameworkStatus(controller.signal);

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

const WORKSPACE_RECORD = {
  id: "b6b25169-8d22-4503-b53c-0f59ff38c992",
  title: "Suspicious IP",
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z",
  status: "open",
  tags: [],
  summary: null,
  severity: null,
  investigation_type: "ipv4",
  investigation_summary: null,
  detection_package: null,
  correlation_summary: null,
};

describe("saveInvestigation", () => {
  it("POSTs the request to the workspace endpoint and returns the saved record", async () => {
    const fetchMock = stubFetch(201, WORKSPACE_RECORD);

    const result = await saveInvestigation({ title: "Suspicious IP", investigation_type: "ipv4" });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/workspace$/);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      title: "Suspicious IP",
      investigation_type: "ipv4",
    });
    expect(result).toEqual(WORKSPACE_RECORD);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(422, { detail: "bad" });
    await expect(
      saveInvestigation({ title: "", investigation_type: "ipv4" }),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(201, WORKSPACE_RECORD);
    const controller = new AbortController();

    await saveInvestigation({ title: "Case", investigation_type: "ipv4" }, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("listInvestigations", () => {
  it("GETs the workspace endpoint with no query string when no filters are given", async () => {
    const fetchMock = stubFetch(200, { investigations: [], total: 0 });

    await listInvestigations();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/workspace$/);
    expect(init.method).toBe("GET");
  });

  it("builds a query string from every given filter", async () => {
    const fetchMock = stubFetch(200, { investigations: [], total: 0 });

    await listInvestigations({
      status: "closed",
      severity: 4,
      investigation_type: "domain",
      tag: "urgent",
      q: "beacon",
    });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    const parsed = new URL(String(url), "http://example.test");
    expect(parsed.searchParams.get("status")).toBe("closed");
    expect(parsed.searchParams.get("severity")).toBe("4");
    expect(parsed.searchParams.get("investigation_type")).toBe("domain");
    expect(parsed.searchParams.get("tag")).toBe("urgent");
    expect(parsed.searchParams.get("q")).toBe("beacon");
  });

  it("omits filters that are not provided", async () => {
    const fetchMock = stubFetch(200, { investigations: [], total: 0 });

    await listInvestigations({ status: "open" });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).not.toContain("severity");
    expect(String(url)).not.toContain("tag");
    expect(String(url)).not.toContain("q=");
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(500, { detail: "boom" });
    await expect(listInvestigations()).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, { investigations: [], total: 0 });
    const controller = new AbortController();

    await listInvestigations({}, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("getInvestigation", () => {
  it("GETs the workspace/{id} endpoint and returns the full record", async () => {
    const fetchMock = stubFetch(200, WORKSPACE_RECORD);

    const result = await getInvestigation(WORKSPACE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/workspace/${WORKSPACE_RECORD.id}$`));
    expect(init.method).toBe("GET");
    expect(result).toEqual(WORKSPACE_RECORD);
  });

  it("URL-encodes the id", async () => {
    const fetchMock = stubFetch(200, WORKSPACE_RECORD);

    await getInvestigation("weird id/with slash");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain(encodeURIComponent("weird id/with slash"));
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(getInvestigation("missing")).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, WORKSPACE_RECORD);
    const controller = new AbortController();

    await getInvestigation(WORKSPACE_RECORD.id, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("updateInvestigation", () => {
  it("PUTs the partial update to workspace/{id} and returns the updated record", async () => {
    const updated = { ...WORKSPACE_RECORD, status: "closed" };
    const fetchMock = stubFetch(200, updated);

    const result = await updateInvestigation(WORKSPACE_RECORD.id, { status: "closed" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/workspace/${WORKSPACE_RECORD.id}$`));
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({ status: "closed" });
    expect(result).toEqual(updated);
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(
      updateInvestigation("missing", { status: "closed" }),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, WORKSPACE_RECORD);
    const controller = new AbortController();

    await updateInvestigation(WORKSPACE_RECORD.id, { status: "closed" }, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("deleteInvestigation", () => {
  it("DELETEs workspace/{id} and resolves with no value", async () => {
    const fetchMock = stubFetch(204, undefined);

    const result = await deleteInvestigation(WORKSPACE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/workspace/${WORKSPACE_RECORD.id}$`));
    expect(init.method).toBe("DELETE");
    expect(result).toBeUndefined();
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(deleteInvestigation("missing")).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(204, undefined);
    const controller = new AbortController();

    await deleteInvestigation(WORKSPACE_RECORD.id, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("getInvestigationTimeline", () => {
  const TIMELINE_PAYLOAD = {
    investigation_id: WORKSPACE_RECORD.id,
    entity_type: "ipv4",
    entity_value: "1.1.1.1",
    generated_at: "2026-07-14T00:00:00Z",
    events: [
      {
        event_id: "evt_abc123",
        timestamp: "2026-07-01T00:00:00Z",
        event_type: "classification",
        title: "Reported malicious by 3 blocklists",
        description: "95",
        source_type: "investigation_evidence",
        source_id: "fnd_1",
        severity: 3,
        evidence_references: ["fnd_1"],
      },
    ],
  };

  it("GETs the workspace/{id}/timeline endpoint and returns the parsed timeline", async () => {
    const fetchMock = stubFetch(200, TIMELINE_PAYLOAD);

    const result = await getInvestigationTimeline(WORKSPACE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/workspace/${WORKSPACE_RECORD.id}/timeline$`));
    expect(init.method).toBe("GET");
    expect(result).toEqual(TIMELINE_PAYLOAD);
  });

  it("URL-encodes the id", async () => {
    const fetchMock = stubFetch(200, TIMELINE_PAYLOAD);

    await getInvestigationTimeline("weird id/with slash");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain(encodeURIComponent("weird id/with slash"));
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(getInvestigationTimeline("missing")).rejects.toBeInstanceOf(ApiError);
  });

  it("returns an empty events array for an investigation with no timestamped evidence", async () => {
    stubFetch(200, { ...TIMELINE_PAYLOAD, events: [] });
    const result = await getInvestigationTimeline(WORKSPACE_RECORD.id);
    expect(result.events).toEqual([]);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, TIMELINE_PAYLOAD);
    const controller = new AbortController();

    await getInvestigationTimeline(WORKSPACE_RECORD.id, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("getInvestigationGraph", () => {
  const GRAPH_PAYLOAD = {
    investigation_id: WORKSPACE_RECORD.id,
    entity_type: "ipv4",
    entity_value: "1.1.1.1",
    generated_at: "2026-07-14T00:00:00Z",
    nodes: [
      {
        node_id: "node_abc123",
        node_type: "ipv4",
        label: "1.1.1.1",
        value: "1.1.1.1",
        severity: 3,
        source_references: ["fnd_1"],
        metadata: {},
      },
    ],
    edges: [],
    node_count: 1,
    edge_count: 0,
    graph_version: "1.0",
  };

  it("GETs the workspace/{id}/graph endpoint and returns the parsed graph", async () => {
    const fetchMock = stubFetch(200, GRAPH_PAYLOAD);

    const result = await getInvestigationGraph(WORKSPACE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/workspace/${WORKSPACE_RECORD.id}/graph$`));
    expect(init.method).toBe("GET");
    expect(result).toEqual(GRAPH_PAYLOAD);
  });

  it("URL-encodes the id", async () => {
    const fetchMock = stubFetch(200, GRAPH_PAYLOAD);

    await getInvestigationGraph("weird id/with slash");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain(encodeURIComponent("weird id/with slash"));
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(getInvestigationGraph("missing")).rejects.toBeInstanceOf(ApiError);
  });

  it("returns an empty graph for an investigation with no supported evidence", async () => {
    stubFetch(200, { ...GRAPH_PAYLOAD, nodes: [], edges: [], node_count: 0, edge_count: 0 });
    const result = await getInvestigationGraph(WORKSPACE_RECORD.id);
    expect(result.nodes).toEqual([]);
    expect(result.edges).toEqual([]);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, GRAPH_PAYLOAD);
    const controller = new AbortController();

    await getInvestigationGraph(WORKSPACE_RECORD.id, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("getInvestigationReport", () => {
  const REPORT_PAYLOAD = {
    report_schema_version: "1.0",
    investigation: WORKSPACE_RECORD,
    timeline: {
      investigation_id: WORKSPACE_RECORD.id,
      entity_type: "ipv4",
      entity_value: "",
      generated_at: "2026-07-14T00:00:00Z",
      events: [],
    },
    graph: {
      investigation_id: WORKSPACE_RECORD.id,
      entity_type: "ipv4",
      entity_value: "",
      generated_at: "2026-07-14T00:00:00Z",
      nodes: [],
      edges: [],
      node_count: 0,
      edge_count: 0,
      graph_version: "1.0",
    },
  };

  it("GETs the workspace/{id}/export endpoint and returns the parsed report", async () => {
    const fetchMock = stubFetch(200, REPORT_PAYLOAD);

    const result = await getInvestigationReport(WORKSPACE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/workspace/${WORKSPACE_RECORD.id}/export$`));
    expect(init.method).toBe("GET");
    expect(result).toEqual(REPORT_PAYLOAD);
  });

  it("URL-encodes the id", async () => {
    const fetchMock = stubFetch(200, REPORT_PAYLOAD);

    await getInvestigationReport("weird id/with slash");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain(encodeURIComponent("weird id/with slash"));
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(getInvestigationReport("missing")).rejects.toBeInstanceOf(ApiError);
  });

  it("bundles the investigation, timeline, and graph sections", async () => {
    stubFetch(200, REPORT_PAYLOAD);
    const result = await getInvestigationReport(WORKSPACE_RECORD.id);
    expect(result.investigation).toEqual(WORKSPACE_RECORD);
    expect(result.timeline.investigation_id).toBe(WORKSPACE_RECORD.id);
    expect(result.graph.investigation_id).toBe(WORKSPACE_RECORD.id);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, REPORT_PAYLOAD);
    const controller = new AbortController();

    await getInvestigationReport(WORKSPACE_RECORD.id, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

// --- Case Management (Phase 9.0) ---

const CASE_RECORD = {
  id: "b2a5e3c1-1234-4abc-9def-0123456789ab",
  title: "Suspicious login activity",
  description: null,
  status: "open",
  priority: "medium",
  created_at: "2026-07-17T00:00:00Z",
  updated_at: "2026-07-17T00:00:00Z",
  owner: null,
  tags: [],
  linked_workspace_ids: [],
  notes: [],
  metadata: {},
};

describe("createCase", () => {
  it("POSTs the request to the cases endpoint and returns the created case", async () => {
    const fetchMock = stubFetch(201, CASE_RECORD);

    const result = await createCase({ title: "Suspicious login activity" });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/cases$/);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ title: "Suspicious login activity" });
    expect(result).toEqual(CASE_RECORD);
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(422, { detail: "bad" });
    await expect(createCase({ title: "" })).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(201, CASE_RECORD);
    const controller = new AbortController();

    await createCase({ title: "Case" }, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("listCases", () => {
  it("GETs the cases endpoint with no query string when no filters are given", async () => {
    const fetchMock = stubFetch(200, { cases: [], total: 0 });

    await listCases();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(/\/cases$/);
    expect(init.method).toBe("GET");
  });

  it("builds a query string from every given filter", async () => {
    const fetchMock = stubFetch(200, { cases: [], total: 0 });

    await listCases({
      status: "closed",
      priority: "high",
      tag: "urgent",
      owner: "alice",
      title: "login",
    });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    const parsed = new URL(String(url), "http://example.test");
    expect(parsed.searchParams.get("status")).toBe("closed");
    expect(parsed.searchParams.get("priority")).toBe("high");
    expect(parsed.searchParams.get("tag")).toBe("urgent");
    expect(parsed.searchParams.get("owner")).toBe("alice");
    expect(parsed.searchParams.get("title")).toBe("login");
  });

  it("omits filters that are not provided", async () => {
    const fetchMock = stubFetch(200, { cases: [], total: 0 });

    await listCases({ status: "open" });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).not.toContain("priority");
    expect(String(url)).not.toContain("owner");
  });

  it("throws ApiError on a non-2xx response", async () => {
    stubFetch(500, { detail: "boom" });
    await expect(listCases()).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, { cases: [], total: 0 });
    const controller = new AbortController();

    await listCases({}, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("getCase", () => {
  it("GETs the cases/{id} endpoint and returns the full record", async () => {
    const fetchMock = stubFetch(200, CASE_RECORD);

    const result = await getCase(CASE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/cases/${CASE_RECORD.id}$`));
    expect(init.method).toBe("GET");
    expect(result).toEqual(CASE_RECORD);
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(getCase("missing")).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, CASE_RECORD);
    const controller = new AbortController();

    await getCase(CASE_RECORD.id, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("updateCase", () => {
  it("PATCHes the partial update to cases/{id} and returns the updated case", async () => {
    const updated = { ...CASE_RECORD, status: "closed" };
    const fetchMock = stubFetch(200, updated);

    const result = await updateCase(CASE_RECORD.id, { status: "closed" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/cases/${CASE_RECORD.id}$`));
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({ status: "closed" });
    expect(result).toEqual(updated);
  });

  it("throws ApiError on a 409 (invalid status transition)", async () => {
    stubFetch(409, { detail: "invalid transition" });
    await expect(
      updateCase(CASE_RECORD.id, { status: "resolved" }),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(updateCase("missing", { title: "x" })).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(200, CASE_RECORD);
    const controller = new AbortController();

    await updateCase(CASE_RECORD.id, { title: "x" }, controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});

describe("deleteCase", () => {
  it("DELETEs cases/{id} and resolves with no value", async () => {
    const fetchMock = stubFetch(204, undefined);

    const result = await deleteCase(CASE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/cases/${CASE_RECORD.id}$`));
    expect(init.method).toBe("DELETE");
    expect(result).toBeUndefined();
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(deleteCase("missing")).rejects.toBeInstanceOf(ApiError);
  });
});

describe("linkWorkspaceToCase", () => {
  it("POSTs the workspace id to cases/{id}/workspace and returns the updated case", async () => {
    const linked = { ...CASE_RECORD, linked_workspace_ids: [WORKSPACE_RECORD.id] };
    const fetchMock = stubFetch(200, linked);

    const result = await linkWorkspaceToCase(CASE_RECORD.id, WORKSPACE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/cases/${CASE_RECORD.id}/workspace$`));
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ workspace_id: WORKSPACE_RECORD.id });
    expect(result).toEqual(linked);
  });

  it("throws ApiError on a 404 (nonexistent investigation)", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(
      linkWorkspaceToCase(CASE_RECORD.id, "missing"),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it("surfaces a friendly message on a 404, matching put/patch/del", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(linkWorkspaceToCase(CASE_RECORD.id, "missing")).rejects.toThrow("Not found.");
  });
});

describe("unlinkWorkspaceFromCase", () => {
  it("DELETEs cases/{id}/workspace/{workspaceId} and returns the updated case", async () => {
    const fetchMock = stubFetch(200, CASE_RECORD);

    const result = await unlinkWorkspaceFromCase(CASE_RECORD.id, WORKSPACE_RECORD.id);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(
      new RegExp(`/cases/${CASE_RECORD.id}/workspace/${WORKSPACE_RECORD.id}$`),
    );
    expect(init.method).toBe("DELETE");
    expect(result).toEqual(CASE_RECORD);
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(
      unlinkWorkspaceFromCase("missing", WORKSPACE_RECORD.id),
    ).rejects.toBeInstanceOf(ApiError);
  });
});

describe("addCaseNote", () => {
  it("POSTs author/content to cases/{id}/notes and returns the updated case", async () => {
    const noted = {
      ...CASE_RECORD,
      notes: [{ author: "analyst", timestamp: "2026-07-17T01:00:00Z", content: "Investigating." }],
    };
    const fetchMock = stubFetch(201, noted);

    const result = await addCaseNote(CASE_RECORD.id, "analyst", "Investigating.");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toMatch(new RegExp(`/cases/${CASE_RECORD.id}/notes$`));
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      author: "analyst",
      content: "Investigating.",
    });
    expect(result).toEqual(noted);
  });

  it("throws ApiError on a 404", async () => {
    stubFetch(404, { detail: "not found" });
    await expect(addCaseNote("missing", "analyst", "x")).rejects.toBeInstanceOf(ApiError);
  });

  it("passes the abort signal through to fetch", async () => {
    const fetchMock = stubFetch(201, CASE_RECORD);
    const controller = new AbortController();

    await addCaseNote(CASE_RECORD.id, "analyst", "note", controller.signal);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
  });
});
