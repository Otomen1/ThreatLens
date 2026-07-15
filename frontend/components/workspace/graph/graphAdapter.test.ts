import { describe, expect, it } from "vitest";

import type { EvidenceGraph, GraphEdge, GraphNode } from "@/lib/api";
import {
  EMPTY_FILTERS,
  hasActiveFilters,
  matchesQuery,
  toFlowGraph,
  visibleEdgeIds,
  visibleNodeIds,
  type GraphFilters,
} from "./graphAdapter";

function node(overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    node_id: "node_a",
    node_type: "ipv4",
    label: "1.2.3.4",
    value: "1.2.3.4",
    severity: null,
    source_references: [],
    metadata: {},
    ...overrides,
  };
}

function edge(overrides: Partial<GraphEdge> = {}): GraphEdge {
  return {
    edge_id: "edge_a",
    source_node_id: "node_a",
    target_node_id: "node_b",
    relationship_type: "associated_with",
    explanation: "",
    evidence_references: [],
    source_references: [],
    ...overrides,
  };
}

function graph(nodes: GraphNode[], edges: GraphEdge[] = []): EvidenceGraph {
  return {
    investigation_id: "11111111-1111-1111-1111-111111111111",
    entity_type: "ipv4",
    entity_value: "1.2.3.4",
    generated_at: "2026-01-01T00:00:00Z",
    nodes,
    edges,
    node_count: nodes.length,
    edge_count: edges.length,
    graph_version: "1.0",
  };
}

describe("toFlowGraph", () => {
  it("preserves every node with its id and data untouched", () => {
    const a = node({ node_id: "node_a", value: "1.2.3.4" });
    const b = node({ node_id: "node_b", node_type: "malware_family", value: "Emotet" });
    const { nodes } = toFlowGraph(graph([a, b]));

    expect(nodes).toHaveLength(2);
    expect(nodes.map((n) => n.id).sort()).toEqual(["node_a", "node_b"]);
    expect(nodes.find((n) => n.id === "node_a")?.data.apiNode).toEqual(a);
    expect(nodes.find((n) => n.id === "node_b")?.data.apiNode).toEqual(b);
  });

  it("preserves every edge with its id, endpoints, and relationship type untouched", () => {
    const a = node({ node_id: "node_a" });
    const b = node({ node_id: "node_b" });
    const e = edge({ edge_id: "edge_a", source_node_id: "node_a", target_node_id: "node_b" });
    const { edges } = toFlowGraph(graph([a, b], [e]));

    expect(edges).toHaveLength(1);
    expect(edges[0].id).toBe("edge_a");
    expect(edges[0].source).toBe("node_a");
    expect(edges[0].target).toBe("node_b");
    expect(edges[0].data?.apiEdge).toEqual(e);
  });

  it("never invents nodes beyond the API response", () => {
    const g = graph([node({ node_id: "node_a" }), node({ node_id: "node_b" })]);
    const { nodes } = toFlowGraph(g);
    expect(nodes).toHaveLength(g.nodes.length);
  });

  it("never invents edges beyond the API response", () => {
    const a = node({ node_id: "node_a" });
    const b = node({ node_id: "node_b" });
    const g = graph([a, b], [edge()]);
    const { edges } = toFlowGraph(g);
    expect(edges).toHaveLength(g.edges.length);
  });

  it("handles a graph with nodes but no edges", () => {
    const g = graph([node({ node_id: "node_a" }), node({ node_id: "node_b" })], []);
    const { nodes, edges } = toFlowGraph(g);
    expect(nodes).toHaveLength(2);
    expect(edges).toHaveLength(0);
  });

  it("handles an empty graph", () => {
    const { nodes, edges } = toFlowGraph(graph([], []));
    expect(nodes).toHaveLength(0);
    expect(edges).toHaveLength(0);
  });

  it("produces a byte-identical layout across repeated calls (deterministic)", () => {
    const g = graph(
      [
        node({ node_id: "node_a", node_type: "ipv4" }),
        node({ node_id: "node_b", node_type: "malware_family" }),
        node({ node_id: "node_c", node_type: "ipv4" }),
      ],
      [edge({ source_node_id: "node_a", target_node_id: "node_b" })],
    );
    const first = toFlowGraph(g);
    const second = toFlowGraph(g);
    expect(first).toEqual(second);
  });

  it("assigns the same node the same position regardless of list order", () => {
    const a = node({ node_id: "node_a", node_type: "ipv4" });
    const b = node({ node_id: "node_b", node_type: "malware_family" });
    const forward = toFlowGraph(graph([a, b]));
    const backward = toFlowGraph(graph([b, a]));
    const posA1 = forward.nodes.find((n) => n.id === "node_a")?.position;
    const posA2 = backward.nodes.find((n) => n.id === "node_a")?.position;
    expect(posA1).toEqual(posA2);
  });

  it("edge label is a display-only transform of the existing relationship type", () => {
    const e = edge({ relationship_type: "communicates_with" });
    const { edges } = toFlowGraph(graph([node()], [e]));
    expect(edges[0].label).toBe("communicates with");
    // the underlying data still carries the exact, unmodified relationship type
    expect(edges[0].data?.apiEdge.relationship_type).toBe("communicates_with");
  });
});

describe("matchesQuery", () => {
  it("matches on value case-insensitively", () => {
    expect(matchesQuery(node({ value: "Emotet" }), "emo")).toBe(true);
  });

  it("matches on node_type", () => {
    expect(matchesQuery(node({ node_type: "malware_family" }), "malware")).toBe(true);
  });

  it("does not match unrelated text", () => {
    expect(matchesQuery(node({ value: "1.2.3.4", node_type: "ipv4" }), "emotet")).toBe(false);
  });

  it("an empty query matches everything", () => {
    expect(matchesQuery(node(), "")).toBe(true);
    expect(matchesQuery(node(), "   ")).toBe(true);
  });
});

describe("visibleNodeIds", () => {
  const a = node({ node_id: "node_a", node_type: "ipv4", value: "1.2.3.4", severity: 3 });
  const b = node({ node_id: "node_b", node_type: "malware_family", value: "Emotet", severity: null });

  it("with no filters, every node is visible", () => {
    expect(visibleNodeIds([a, b], EMPTY_FILTERS)).toEqual(new Set(["node_a", "node_b"]));
  });

  it("a node-type filter restricts to matching types", () => {
    const filters: GraphFilters = { ...EMPTY_FILTERS, nodeTypes: new Set(["malware_family"]) };
    expect(visibleNodeIds([a, b], filters)).toEqual(new Set(["node_b"]));
  });

  it("a severity filter restricts to matching severities, including null", () => {
    const filters: GraphFilters = { ...EMPTY_FILTERS, severities: new Set([null]) };
    expect(visibleNodeIds([a, b], filters)).toEqual(new Set(["node_b"]));
  });

  it("a search query restricts to matching nodes", () => {
    const filters: GraphFilters = { ...EMPTY_FILTERS, query: "emotet" };
    expect(visibleNodeIds([a, b], filters)).toEqual(new Set(["node_b"]));
  });

  it("filters combine with AND semantics", () => {
    const filters: GraphFilters = {
      ...EMPTY_FILTERS,
      nodeTypes: new Set(["ipv4"]),
      severities: new Set([3]),
    };
    expect(visibleNodeIds([a, b], filters)).toEqual(new Set(["node_a"]));
  });
});

describe("visibleEdgeIds", () => {
  const e = edge({ edge_id: "edge_a", source_node_id: "node_a", target_node_id: "node_b" });

  it("an edge is visible when both endpoints are visible", () => {
    const visibleNodes = new Set(["node_a", "node_b"]);
    expect(visibleEdgeIds([e], visibleNodes, EMPTY_FILTERS)).toEqual(new Set(["edge_a"]));
  });

  it("an edge is hidden when either endpoint is hidden", () => {
    const visibleNodes = new Set(["node_a"]);
    expect(visibleEdgeIds([e], visibleNodes, EMPTY_FILTERS)).toEqual(new Set());
  });

  it("a relationship-type filter restricts to matching edges", () => {
    const visibleNodes = new Set(["node_a", "node_b"]);
    const filters: GraphFilters = { ...EMPTY_FILTERS, relationshipTypes: new Set(["exploits"]) };
    expect(visibleEdgeIds([e], visibleNodes, filters)).toEqual(new Set());
  });

  it("never invents an edge that isn't in the input list", () => {
    const visibleNodes = new Set(["node_a", "node_b"]);
    const result = visibleEdgeIds([e], visibleNodes, EMPTY_FILTERS);
    expect(result.size).toBeLessThanOrEqual(1);
    for (const id of result) expect(id).toBe("edge_a");
  });
});

describe("hasActiveFilters", () => {
  it("is false for the empty filter set", () => {
    expect(hasActiveFilters(EMPTY_FILTERS)).toBe(false);
  });

  it("is true when a query is present", () => {
    expect(hasActiveFilters({ ...EMPTY_FILTERS, query: "x" })).toBe(true);
  });

  it("is true when any type/severity/relationship set is non-empty", () => {
    expect(hasActiveFilters({ ...EMPTY_FILTERS, nodeTypes: new Set(["ipv4"]) })).toBe(true);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, severities: new Set([1]) })).toBe(true);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, relationshipTypes: new Set(["uses"]) })).toBe(true);
  });
});
