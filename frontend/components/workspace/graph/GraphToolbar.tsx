"use client";

// Search + filter controls for the Evidence Graph (Phase 8.3). Operates
// only on already-loaded graph data — no backend search endpoint, no fuzzy
// or semantic matching, no AI. Filtering only changes which already-existing
// nodes/edges are visible; it never mutates the underlying EvidenceGraph.

import { useState } from "react";

import type { GraphNode as ApiGraphNode } from "@/lib/api";
import { severityLabel } from "@/lib/investigation";
import { IconButton } from "@/components/investigation/shared/DetectionDisclosure";
import { EMPTY_FILTERS, hasActiveFilters, type GraphFilters } from "./graphAdapter";

function toggleSetValue<T>(set: ReadonlySet<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

function FilterChip({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors ${
        active
          ? "border-sky-500 text-sky-300 bg-sky-500/10 font-semibold"
          : "border-zinc-700 text-zinc-400 hover:border-zinc-600"
      }`}
    >
      {label}
    </button>
  );
}

export function GraphToolbar({
  filters,
  onFiltersChange,
  nodeTypeOptions,
  relationshipTypeOptions,
  severityOptions,
  searchResults,
  onSelectResult,
}: {
  filters: GraphFilters;
  onFiltersChange: (filters: GraphFilters) => void;
  nodeTypeOptions: string[];
  relationshipTypeOptions: string[];
  severityOptions: (number | null)[];
  searchResults: ApiGraphNode[];
  onSelectResult: (nodeId: string) => void;
}) {
  const [searchOpen, setSearchOpen] = useState(false);

  return (
    <div className="space-y-2">
      <div className="relative">
        <input
          type="text"
          value={filters.query}
          onChange={(e) => {
            onFiltersChange({ ...filters, query: e.target.value });
            setSearchOpen(true);
          }}
          onFocus={() => setSearchOpen(true)}
          onBlur={() => setTimeout(() => setSearchOpen(false), 150)}
          placeholder="Search nodes by value or type…"
          aria-label="Search graph nodes"
          className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-600"
        />
        {searchOpen && filters.query.trim() && (
          <ul className="absolute z-10 mt-1 w-full max-h-48 overflow-y-auto rounded-lg border border-zinc-700 bg-zinc-900 shadow-lg">
            {searchResults.length === 0 && (
              <li className="px-3 py-1.5 text-xs text-zinc-600">No matching nodes</li>
            )}
            {searchResults.slice(0, 20).map((node) => (
              <li key={node.node_id}>
                <button
                  type="button"
                  onMouseDown={() => onSelectResult(node.node_id)}
                  className="w-full text-left px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 truncate"
                >
                  <span className="text-zinc-500 mr-1.5">
                    {node.node_type.replace(/_/g, " ")}
                  </span>
                  {node.label}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        {nodeTypeOptions.length > 0 && (
          <>
            <span className="text-[10px] text-zinc-600">Type:</span>
            {nodeTypeOptions.map((type) => (
              <FilterChip
                key={`type-${type}`}
                label={type.replace(/_/g, " ")}
                active={filters.nodeTypes.has(type)}
                onClick={() =>
                  onFiltersChange({ ...filters, nodeTypes: toggleSetValue(filters.nodeTypes, type) })
                }
              />
            ))}
          </>
        )}
        {severityOptions.length > 0 && (
          <>
            <span className="text-[10px] text-zinc-600 ml-1">Severity:</span>
            {severityOptions.map((sev) => (
              <FilterChip
                key={`sev-${sev}`}
                label={sev === null ? "none" : severityLabel(sev)}
                active={filters.severities.has(sev)}
                onClick={() =>
                  onFiltersChange({
                    ...filters,
                    severities: toggleSetValue(filters.severities, sev),
                  })
                }
              />
            ))}
          </>
        )}
        {relationshipTypeOptions.length > 0 && (
          <>
            <span className="text-[10px] text-zinc-600 ml-1">Relationship:</span>
            {relationshipTypeOptions.map((type) => (
              <FilterChip
                key={`rel-${type}`}
                label={type.replace(/_/g, " ")}
                active={filters.relationshipTypes.has(type)}
                onClick={() =>
                  onFiltersChange({
                    ...filters,
                    relationshipTypes: toggleSetValue(filters.relationshipTypes, type),
                  })
                }
              />
            ))}
          </>
        )}
        {hasActiveFilters(filters) && (
          <IconButton label="Reset filters" onClick={() => onFiltersChange(EMPTY_FILTERS)} />
        )}
      </div>
    </div>
  );
}
