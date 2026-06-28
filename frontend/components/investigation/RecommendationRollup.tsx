"use client";

import { useState } from "react";

import type { Recommendation } from "@/lib/api";
import { recommendationCategoryClasses, titleCase } from "@/lib/investigation";

interface Props {
  recommendations: Recommendation[];
}

/**
 * The deduplicated recommendation rollup. Rendered in the exact order the
 * backend returns (already priority-sorted) — never re-sorted client-side.
 */
export function RecommendationRollup({ recommendations }: Props) {
  if (recommendations.length === 0) return null;

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
      aria-label="Recommendations"
    >
      <h2 className="text-sm font-semibold text-white mb-3">
        Recommendations
        <span className="ml-2 text-xs font-normal text-zinc-500">({recommendations.length})</span>
      </h2>
      <div className="space-y-2">
        {recommendations.map((rec, i) => (
          <RecommendationRow key={`${rec.action}:${rec.target_value}:${i}`} rec={rec} />
        ))}
      </div>
    </section>
  );
}

function RecommendationRow({ rec }: { rec: Recommendation }) {
  const [expanded, setExpanded] = useState(false);
  const count = rec.finding_ids.length;

  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-zinc-800/60 transition-colors"
        aria-expanded={expanded}
      >
        <span
          className={`shrink-0 px-2 py-0.5 rounded-md border text-[11px] font-medium capitalize ${recommendationCategoryClasses(rec.category)}`}
        >
          {rec.category}
        </span>
        <span className="flex-1 min-w-0 text-sm text-zinc-200 truncate">{titleCase(rec.action)}</span>
        <span className="shrink-0 text-[11px] text-zinc-500 hidden sm:inline">
          {count} finding{count === 1 ? "" : "s"}
        </span>
        <span className="shrink-0 px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700/60 text-[11px] text-zinc-400 font-mono">
          P{rec.priority}
        </span>
        <Chevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="px-3 pb-3 pt-1 border-t border-zinc-700/40 space-y-2">
          <p className="text-xs text-zinc-400 leading-relaxed">{rec.rationale}</p>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] uppercase tracking-wider text-zinc-600">From</span>
            {rec.finding_ids.map((id) => (
              <span
                key={id}
                className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700/60 text-[10px] font-mono text-zinc-500"
              >
                {id}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Chevron({ expanded }: { expanded: boolean }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 text-zinc-500 transition-transform duration-150 ${expanded ? "rotate-180" : ""}`}
      aria-hidden
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
