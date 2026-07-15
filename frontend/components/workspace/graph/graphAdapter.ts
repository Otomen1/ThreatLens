// Pure, deterministic presentation adapter (Phase 8.3): converts the
// existing `EvidenceGraph` API response into React Flow's node/edge shape,
// plus presentation-only search/filter helpers. Every id, type, value, and
// reference is copied verbatim from the API model — this file invents no
// entity, no relationship, and no severity; it only decides where a node
// sits on screen and which already-existing elements are currently visible.

import type { Edge, Node } from "@xyflow/react";

import type { EvidenceGraph, GraphEdge, GraphNode as ApiGraphNode } from "@/lib/api";

export interface GraphNodeData extends Record<string, unknown> {
  apiNode: ApiGraphNode;
}

export interface GraphEdgeData extends Record<string, unknown> {
  apiEdge: GraphEdge;
}

export const EVIDENCE_NODE_TYPE = "evidenceNode";

export type FlowNode = Node<GraphNodeData, typeof EVIDENCE_NODE_TYPE>;
export type FlowEdge = Edge<GraphEdgeData>;

const COLUMN_WIDTH = 220;
const ROW_HEIGHT = 84;

/**
 * Deterministic column-by-type layout: one column per distinct `node_type`
 * (columns ordered alphabetically — the same key the backend's own
 * `sort_nodes` already orders by), nodes stacked top-to-bottom within their
 * column in the exact order the API returned them. No physics, no
 * iteration, no randomness, no clustering/centrality computation — position
 * is a pure function of `(node_type, index-within-type)`, so the same
 * `EvidenceGraph` always lays out identically. Column order groups by an
 * existing data field; it is not a claim about chronology or causality.
 */
function layoutPositions(nodes: readonly ApiGraphNode[]): Map<string, { x: number; y: number }> {
  const types = Array.from(new Set(nodes.map((n) => n.node_type))).sort();
  const columnByType = new Map(types.map((t, i) => [t, i]));
  const rowByType = new Map<string, number>();
  const positions = new Map<string, { x: number; y: number }>();

  for (const node of nodes) {
    const col = columnByType.get(node.node_type) ?? 0;
    const row = rowByType.get(node.node_type) ?? 0;
    positions.set(node.node_id, { x: col * COLUMN_WIDTH, y: row * ROW_HEIGHT });
    rowByType.set(node.node_type, row + 1);
  }
  return positions;
}

/** Converts every existing node/edge into React Flow's shape. Nothing is added or dropped. */
export function toFlowGraph(graph: EvidenceGraph): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const positions = layoutPositions(graph.nodes);

  const nodes: FlowNode[] = graph.nodes.map((apiNode) => ({
    id: apiNode.node_id,
    type: EVIDENCE_NODE_TYPE,
    position: positions.get(apiNode.node_id) ?? { x: 0, y: 0 },
    data: { apiNode },
  }));

  const edges: FlowEdge[] = graph.edges.map((apiEdge) => ({
    id: apiEdge.edge_id,
    source: apiEdge.source_node_id,
    target: apiEdge.target_node_id,
    label: apiEdge.relationship_type.replace(/_/g, " "),
    data: { apiEdge },
  }));

  return { nodes, edges };
}

// --- Search & filter — presentation-only; never mutates the source graph ---

export interface GraphFilters {
  query: string;
  nodeTypes: ReadonlySet<string>;
  severities: ReadonlySet<number | null>;
  relationshipTypes: ReadonlySet<string>;
}

export const EMPTY_FILTERS: GraphFilters = {
  query: "",
  nodeTypes: new Set(),
  severities: new Set(),
  relationshipTypes: new Set(),
};

export function hasActiveFilters(filters: GraphFilters): boolean {
  return (
    filters.query.trim() !== "" ||
    filters.nodeTypes.size > 0 ||
    filters.severities.size > 0 ||
    filters.relationshipTypes.size > 0
  );
}

/** Matches on the node's own existing `value`/`node_type` — no fuzzy or semantic inference. */
export function matchesQuery(node: ApiGraphNode, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    node.value.toLowerCase().includes(q) ||
    node.label.toLowerCase().includes(q) ||
    node.node_type.toLowerCase().includes(q)
  );
}

/** IDs of nodes that satisfy every active filter (search text, type, severity). */
export function visibleNodeIds(
  nodes: readonly ApiGraphNode[],
  filters: GraphFilters,
): Set<string> {
  const visible = new Set<string>();
  for (const node of nodes) {
    if (!matchesQuery(node, filters.query)) continue;
    if (filters.nodeTypes.size > 0 && !filters.nodeTypes.has(node.node_type)) continue;
    if (filters.severities.size > 0 && !filters.severities.has(node.severity)) continue;
    visible.add(node.node_id);
  }
  return visible;
}

/**
 * IDs of edges whose endpoints are both currently visible and whose own
 * relationship type (if a relationship-type filter is active) matches.
 * An edge is never shown if either endpoint is hidden — React Flow requires
 * both endpoints to exist, and a "floating" edge would misrepresent the
 * filtered view as showing a connection the analyst can't see the ends of.
 */
export function visibleEdgeIds(
  edges: readonly GraphEdge[],
  visibleNodes: ReadonlySet<string>,
  filters: GraphFilters,
): Set<string> {
  const visible = new Set<string>();
  for (const edge of edges) {
    if (!visibleNodes.has(edge.source_node_id) || !visibleNodes.has(edge.target_node_id)) {
      continue;
    }
    if (
      filters.relationshipTypes.size > 0 &&
      !filters.relationshipTypes.has(edge.relationship_type)
    ) {
      continue;
    }
    visible.add(edge.edge_id);
  }
  return visible;
}
