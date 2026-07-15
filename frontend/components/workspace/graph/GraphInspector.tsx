"use client";

// The node/edge detail panel for the Evidence Graph (Phase 8.3). Displays
// only fields already present on the existing `GraphNode`/`GraphEdge` API
// models, verbatim — no generated explanation, no AI, no inferred meaning.

import type { GraphEdge, GraphNode as ApiGraphNode } from "@/lib/api";
import { severityClasses, severityLabel } from "@/lib/investigation";
import { IconButton } from "@/components/investigation/shared/DetectionDisclosure";

export type GraphSelection = { kind: "node"; id: string } | { kind: "edge"; id: string } | null;

export function GraphInspector({
  selection,
  node,
  edge,
  nodesById,
  onClear,
}: {
  selection: GraphSelection;
  node?: ApiGraphNode;
  edge?: GraphEdge;
  nodesById: Map<string, ApiGraphNode>;
  onClear: () => void;
}) {
  if (!selection || (!node && !edge)) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-3 text-xs text-zinc-500">
        Select a node or relationship to inspect its evidence.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-3 space-y-2.5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-zinc-200">
          {selection.kind === "node" ? "Node" : "Relationship"}
        </span>
        <IconButton label="Clear" onClick={onClear} />
      </div>

      {node && (
        <dl className="space-y-1.5">
          <Row label="Node ID" value={node.node_id} mono />
          <Row label="Type" value={node.node_type} />
          <Row label="Value" value={node.value} />
          {node.severity !== null && (
            <div>
              <span className="block text-[9px] uppercase tracking-wider text-zinc-600">
                Severity
              </span>
              <span
                className={`inline-block text-[10px] px-2 py-0.5 rounded-full border ${severityClasses(node.severity)}`}
              >
                {severityLabel(node.severity)}
              </span>
            </div>
          )}
          <Row
            label="Source references"
            value={node.source_references.length > 0 ? node.source_references.join(", ") : "none"}
          />
          {Object.keys(node.metadata).length > 0 && (
            <Row
              label="Metadata"
              value={Object.entries(node.metadata)
                .map(([key, value]) => `${key}: ${String(value)}`)
                .join(" · ")}
            />
          )}
        </dl>
      )}

      {edge && (
        <dl className="space-y-1.5">
          <Row label="Edge ID" value={edge.edge_id} mono />
          <Row label="Relationship" value={edge.relationship_type} />
          <Row
            label="Source"
            value={nodesById.get(edge.source_node_id)?.label ?? edge.source_node_id}
          />
          <Row
            label="Target"
            value={nodesById.get(edge.target_node_id)?.label ?? edge.target_node_id}
          />
          {edge.explanation && <Row label="Explanation" value={edge.explanation} />}
          <Row
            label="Evidence references"
            value={
              edge.evidence_references.length > 0 ? edge.evidence_references.join(", ") : "none"
            }
          />
          <Row
            label="Source references"
            value={edge.source_references.length > 0 ? edge.source_references.join(", ") : "none"}
          />
        </dl>
      )}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <span className="block text-[9px] uppercase tracking-wider text-zinc-600">{label}</span>
      <span className={`block break-words text-xs text-zinc-300 ${mono ? "font-mono" : ""}`}>
        {value}
      </span>
    </div>
  );
}
