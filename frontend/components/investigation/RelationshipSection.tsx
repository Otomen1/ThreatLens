"use client";

import { useState } from "react";

import type { AttributedRelationship } from "@/lib/api";
import { formatRelationship, formatTargetType } from "@/lib/investigation";

interface Props {
  relationships: AttributedRelationship[];
}

const PAGE_SIZE = 12;

export function RelationshipSection({ relationships }: Props) {
  const [showAll, setShowAll] = useState(false);

  if (relationships.length === 0) return null;

  const displayed = showAll ? relationships : relationships.slice(0, PAGE_SIZE);
  const hasMore = relationships.length > PAGE_SIZE;

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
      aria-label="Relationships"
    >
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-white">
          Relationships
          <span className="ml-2 text-xs font-normal text-zinc-500">
            ({relationships.length})
          </span>
        </h2>
      </div>

      <div className="overflow-x-auto -mx-1 px-1">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className="text-left text-[11px] font-medium text-zinc-500 pb-2 pr-4 whitespace-nowrap">
                Relationship
              </th>
              <th className="text-left text-[11px] font-medium text-zinc-500 pb-2 pr-4 whitespace-nowrap">
                Type
              </th>
              <th className="text-left text-[11px] font-medium text-zinc-500 pb-2 pr-4">
                Target
              </th>
              <th className="text-left text-[11px] font-medium text-zinc-500 pb-2 whitespace-nowrap hidden sm:table-cell">
                Source
              </th>
            </tr>
          </thead>
          <tbody>
            {displayed.map((r, i) => (
              <tr
                key={i}
                className="border-b border-zinc-800/40 last:border-0 hover:bg-zinc-800/20 transition-colors"
              >
                <td className="py-2 pr-4 text-zinc-400 capitalize whitespace-nowrap">
                  {formatRelationship(r.relationship.relationship)}
                </td>
                <td className="py-2 pr-4 whitespace-nowrap">
                  <span className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700/60 text-zinc-400">
                    {formatTargetType(r.relationship.target_type)}
                  </span>
                </td>
                <td className="py-2 pr-4 font-mono text-zinc-300 break-all">
                  {r.relationship.target_value}
                </td>
                <td className="py-2 text-zinc-600 whitespace-nowrap hidden sm:table-cell">
                  {r.sources.join(", ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {hasMore && (
        <button
          onClick={() => setShowAll((v) => !v)}
          className="mt-3 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          {showAll
            ? "Show fewer"
            : `Show all ${relationships.length} relationships`}
        </button>
      )}
    </section>
  );
}
