"use client";

// The interactive Evidence Graph visualization (Phase 8.3). Renders the
// existing `EvidenceGraph` API response with React Flow — every node and
// edge on screen exists in `graph.nodes`/`graph.edges` exactly as returned;
// this component adds no entity, no relationship, and no causality of its
// own. Search and filtering only change visibility (a React Flow `hidden`
// flag) — the underlying node/edge lists passed in are never altered.

import { useMemo, useState } from "react";
import {
  Background,
  Controls,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type EdgeMouseHandler,
  type Node,
  type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { EvidenceGraph } from "@/lib/api";
import {
  EMPTY_FILTERS,
  EVIDENCE_NODE_TYPE,
  matchesQuery,
  toFlowGraph,
  visibleEdgeIds,
  visibleNodeIds,
  type GraphFilters,
} from "./graphAdapter";
import { GraphCanvasNode } from "./GraphCanvasNode";
import { GraphInspector, type GraphSelection } from "./GraphInspector";
import { GraphToolbar } from "./GraphToolbar";

const NODE_TYPES = { [EVIDENCE_NODE_TYPE]: GraphCanvasNode };

export function EvidenceGraphView({ graph }: { graph: EvidenceGraph }) {
  const [filters, setFilters] = useState<GraphFilters>(EMPTY_FILTERS);
  const [selection, setSelection] = useState<GraphSelection>(null);

  const { nodes: baseNodes, edges: baseEdges } = useMemo(() => toFlowGraph(graph), [graph]);

  const visibleNodes = useMemo(
    () => visibleNodeIds(graph.nodes, filters),
    [graph.nodes, filters],
  );
  const visibleEdges = useMemo(
    () => visibleEdgeIds(graph.edges, visibleNodes, filters),
    [graph.edges, visibleNodes, filters],
  );

  const flowNodes: Node[] = useMemo(
    () =>
      baseNodes.map((node) => ({
        ...node,
        hidden: !visibleNodes.has(node.id),
        selected: selection?.kind === "node" && selection.id === node.id,
      })),
    [baseNodes, visibleNodes, selection],
  );
  const flowEdges: Edge[] = useMemo(
    () =>
      baseEdges.map((edge) => ({
        ...edge,
        hidden: !visibleEdges.has(edge.id),
        selected: selection?.kind === "edge" && selection.id === edge.id,
        style: selection?.kind === "edge" && selection.id === edge.id
          ? { stroke: "#0ea5e9", strokeWidth: 2 }
          : undefined,
      })),
    [baseEdges, visibleEdges, selection],
  );

  const nodesById = useMemo(
    () => new Map(graph.nodes.map((node) => [node.node_id, node])),
    [graph.nodes],
  );
  const edgesById = useMemo(
    () => new Map(graph.edges.map((edge) => [edge.edge_id, edge])),
    [graph.edges],
  );

  const nodeTypeOptions = useMemo(
    () => Array.from(new Set(graph.nodes.map((node) => node.node_type))).sort(),
    [graph.nodes],
  );
  const relationshipTypeOptions = useMemo(
    () => Array.from(new Set(graph.edges.map((edge) => edge.relationship_type))).sort(),
    [graph.edges],
  );
  const severityOptions = useMemo(
    () =>
      Array.from(new Set(graph.nodes.map((node) => node.severity))).sort(
        (a, b) => (a ?? -1) - (b ?? -1),
      ),
    [graph.nodes],
  );
  const searchResults = useMemo(
    () => (filters.query.trim() ? graph.nodes.filter((node) => matchesQuery(node, filters.query)) : []),
    [graph.nodes, filters.query],
  );

  const onNodeClick: NodeMouseHandler = (_event, node) =>
    setSelection({ kind: "node", id: node.id });
  const onEdgeClick: EdgeMouseHandler = (_event, edge) =>
    setSelection({ kind: "edge", id: edge.id });
  const onPaneClick = () => setSelection(null);

  return (
    <div className="space-y-3">
      <GraphToolbar
        filters={filters}
        onFiltersChange={setFilters}
        nodeTypeOptions={nodeTypeOptions}
        relationshipTypeOptions={relationshipTypeOptions}
        severityOptions={severityOptions}
        searchResults={searchResults}
        onSelectResult={(nodeId) => setSelection({ kind: "node", id: nodeId })}
      />

      <div className="flex flex-col lg:flex-row gap-3">
        <div
          className="h-[420px] flex-1 min-w-0 rounded-xl border border-zinc-800 bg-zinc-950/50 overflow-hidden"
          aria-label="Evidence graph canvas"
        >
          <ReactFlowProvider>
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              nodeTypes={NODE_TYPES}
              onNodeClick={onNodeClick}
              onEdgeClick={onEdgeClick}
              onPaneClick={onPaneClick}
              fitView
              minZoom={0.2}
              maxZoom={2}
              proOptions={{ hideAttribution: true }}
              colorMode="dark"
            >
              <Background gap={24} />
              <Controls showInteractive={false} position="bottom-right" />
            </ReactFlow>
          </ReactFlowProvider>
        </div>

        <div className="lg:w-72 shrink-0">
          <GraphInspector
            selection={selection}
            node={selection?.kind === "node" ? nodesById.get(selection.id) : undefined}
            edge={selection?.kind === "edge" ? edgesById.get(selection.id) : undefined}
            nodesById={nodesById}
            onClear={() => setSelection(null)}
          />
        </div>
      </div>
    </div>
  );
}
