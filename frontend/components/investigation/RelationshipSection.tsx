"use client";

import { useState } from "react";

import type { AttributedRelationship } from "@/lib/api";
import { formatRelationship, groupRelationshipsByTarget } from "@/lib/investigation";

interface Props {
  relationships: AttributedRelationship[];
}

const PAGE_SIZE = 12;

export function RelationshipSection({ relationships }: Props) {
  const [showAll, setShowAll] = useState(false);

  if (relationships.length === 0) return null;

  const displayed = showAll ? relationships : relationships.slice(0, PAGE_SIZE);
  const hasMore = relationships.length > PAGE_SIZE;
  const groups = groupRelationshipsByTarget(displayed);

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
      aria-label="Relationships"
    >
      <h2 className="text-sm font-semibold text-white mb-4">
        Relationships
        <span className="ml-2 text-xs font-normal text-zinc-500">
          ({relationships.length})
        </span>
      </h2>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {groups.map((group) => (
          <div
            key={group.targetType}
            className="rounded-xl border border-zinc-800 bg-zinc-950/40 overflow-hidden"
          >
            <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 bg-zinc-800/30">
              <span className="text-xs font-medium text-zinc-300">{group.label}</span>
              <span className="text-[10px] font-mono text-zinc-500 bg-zinc-800 rounded-full px-1.5 py-0.5">
                {group.items.length}
              </span>
            </div>
            <ul className="divide-y divide-zinc-800/60">
              {group.items.map((r, i) => (
                <li key={i} className="px-3 py-2 text-xs">
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-zinc-500 capitalize shrink-0">
                      {formatRelationship(r.relationship.relationship)}
                    </span>
                    <span className="font-mono text-zinc-300 break-all">
                      {r.relationship.target_value}
                    </span>
                  </div>
                  <p className="text-[10px] text-zinc-600 mt-0.5">{r.sources.join(", ")}</p>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {hasMore && (
        <button
          onClick={() => setShowAll((v) => !v)}
          className="mt-3 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          {showAll ? "Show fewer" : `Show all ${relationships.length} relationships`}
        </button>
      )}
    </section>
  );
}
