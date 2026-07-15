// Evidence Relationship Summary (Phase 8.4): a concise textual/tabular
// summary of the existing EvidenceGraph — not the interactive React Flow
// canvas (Phase 8.3), which has no print-friendly representation and isn't
// required to for this report to remain useful. Every node/edge shown is
// copied verbatim from the existing graph contract; node/edge ids are the
// same content-addressed ids the interactive view and the JSON export use.

import type { EvidenceGraph, GraphNode } from "@/lib/api";
import { severityClasses, severityLabel } from "@/lib/investigation";

export interface NodeTypeCount {
  type: string;
  count: number;
}

/** Count nodes per distinct `node_type`, alphabetically ordered for determinism. */
export function countNodesByType(nodes: GraphNode[]): NodeTypeCount[] {
  const counts = new Map<string, number>();
  for (const node of nodes) counts.set(node.node_type, (counts.get(node.node_type) ?? 0) + 1);
  return [...counts.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => a.type.localeCompare(b.type));
}

export function ReportGraphSummary({ graph }: { graph: EvidenceGraph }) {
  const typeCounts = countNodesByType(graph.nodes);
  const nodesById = new Map(graph.nodes.map((n) => [n.node_id, n]));

  return (
    <section className="print:break-inside-avoid" aria-label="Evidence relationship summary">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600 mb-2">
        Evidence Relationship Summary
        <span className="ml-2 font-normal normal-case text-zinc-600 print:text-zinc-500">
          ({graph.node_count} nodes · {graph.edge_count} edges)
        </span>
      </h2>

      {graph.node_count === 0 ? (
        <p className="text-sm text-zinc-500 print:text-zinc-600">
          No evidence-supported entities or relationships were found for this investigation.
        </p>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-1.5">
            {typeCounts.map(({ type, count }) => (
              <span
                key={type}
                className="px-2 py-0.5 rounded-full border border-zinc-700/60 print:border-zinc-400 bg-zinc-800/40 print:bg-white text-[11px] text-zinc-300 print:text-black"
              >
                {type.replace(/_/g, " ")} · {count}
              </span>
            ))}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wider text-zinc-500 print:text-zinc-600 border-b border-zinc-800 print:border-zinc-300">
                  <th className="py-1 pr-3 font-medium">Entity</th>
                  <th className="py-1 pr-3 font-medium">Type</th>
                  <th className="py-1 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>
                {graph.nodes.map((node) => (
                  <tr
                    key={node.node_id}
                    className="border-b border-zinc-800/60 print:border-zinc-200"
                  >
                    <td className="py-1.5 pr-3 text-zinc-200 print:text-black break-words">
                      {node.label}
                    </td>
                    <td className="py-1.5 pr-3 text-zinc-500 print:text-zinc-600 whitespace-nowrap">
                      {node.node_type.replace(/_/g, " ")}
                    </td>
                    <td className="py-1.5 whitespace-nowrap">
                      {node.severity !== null && (
                        <span
                          className={`px-1.5 py-0.5 rounded-full border print:border-zinc-400 print:bg-white text-[10px] ${severityClasses(node.severity)}`}
                        >
                          {severityLabel(node.severity)}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {graph.edges.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="text-left text-[10px] uppercase tracking-wider text-zinc-500 print:text-zinc-600 border-b border-zinc-800 print:border-zinc-300">
                    <th className="py-1 pr-3 font-medium">Source</th>
                    <th className="py-1 pr-3 font-medium">Relationship</th>
                    <th className="py-1 font-medium">Target</th>
                  </tr>
                </thead>
                <tbody>
                  {graph.edges.map((edge) => (
                    <tr
                      key={edge.edge_id}
                      className="border-b border-zinc-800/60 print:border-zinc-200"
                    >
                      <td className="py-1.5 pr-3 text-zinc-200 print:text-black break-words">
                        {nodesById.get(edge.source_node_id)?.label ?? edge.source_node_id}
                      </td>
                      <td className="py-1.5 pr-3 text-zinc-500 print:text-zinc-600 whitespace-nowrap">
                        {edge.relationship_type.replace(/_/g, " ")}
                      </td>
                      <td className="py-1.5 text-zinc-200 print:text-black break-words">
                        {nodesById.get(edge.target_node_id)?.label ?? edge.target_node_id}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
