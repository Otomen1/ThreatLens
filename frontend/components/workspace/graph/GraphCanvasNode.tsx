"use client";

// The custom React Flow node renderer for one Evidence Graph node (Phase
// 8.3). Purely presentational: every field it shows (`node_type`, `label`,
// `value`, `severity`) is copied straight from the existing `GraphNode` API
// model — nothing here computes or infers anything about the entity.

import { Handle, Position, type NodeProps } from "@xyflow/react";

import { severityClasses, severityLabel } from "@/lib/investigation";
import type { FlowNode } from "./graphAdapter";

export function GraphCanvasNode({ data, selected }: NodeProps<FlowNode>) {
  const { apiNode } = data;

  return (
    <div
      className={`w-52 rounded-lg border px-2.5 py-2 text-xs shadow-sm transition-colors ${
        selected ? "border-sky-500 bg-sky-500/10" : "border-zinc-700 bg-zinc-900"
      }`}
    >
      <Handle type="target" position={Position.Left} className="!bg-zinc-600 !border-zinc-500" />
      <div className="flex items-center gap-1.5 mb-1 flex-wrap">
        <span className="text-[9px] uppercase tracking-wide text-zinc-400 bg-zinc-800 rounded px-1.5 py-0.5 shrink-0">
          {apiNode.node_type.replace(/_/g, " ")}
        </span>
        {apiNode.severity !== null && (
          <span
            className={`text-[9px] px-1.5 py-0.5 rounded-full border shrink-0 ${severityClasses(apiNode.severity)}`}
          >
            {severityLabel(apiNode.severity)}
          </span>
        )}
      </div>
      <div className="text-zinc-200 truncate" title={apiNode.value}>
        {apiNode.label}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-zinc-600 !border-zinc-500" />
    </div>
  );
}
