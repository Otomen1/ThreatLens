import { describe, expect, it } from "vitest";

import type { GraphNode } from "@/lib/api";
import { countNodesByType } from "./ReportGraphSummary";

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

describe("countNodesByType", () => {
  it("returns an empty list for no nodes", () => {
    expect(countNodesByType([])).toEqual([]);
  });

  it("counts one node per its own type", () => {
    expect(countNodesByType([node({ node_type: "ipv4" })])).toEqual([
      { type: "ipv4", count: 1 },
    ]);
  });

  it("groups multiple nodes of the same type", () => {
    const nodes = [
      node({ node_id: "a", node_type: "ipv4" }),
      node({ node_id: "b", node_type: "ipv4" }),
    ];
    expect(countNodesByType(nodes)).toEqual([{ type: "ipv4", count: 2 }]);
  });

  it("sorts distinct types alphabetically regardless of input order", () => {
    const nodes = [
      node({ node_id: "a", node_type: "malware_family" }),
      node({ node_id: "b", node_type: "correlation_observation" }),
      node({ node_id: "c", node_type: "ipv4" }),
    ];
    expect(countNodesByType(nodes).map((c) => c.type)).toEqual([
      "correlation_observation",
      "ipv4",
      "malware_family",
    ]);
  });

  it("never invents a type beyond what the nodes carry", () => {
    const nodes = [node({ node_type: "ipv4" }), node({ node_id: "b", node_type: "domain" })];
    const result = countNodesByType(nodes);
    const total = result.reduce((sum, c) => sum + c.count, 0);
    expect(total).toBe(nodes.length);
  });
});
