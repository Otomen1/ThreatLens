"use client";

import { useState } from "react";

import type { AggregatedResult } from "@/lib/api";

interface Props {
  threatIntelligence: AggregatedResult;
  knowledge: AggregatedResult;
}

export function AdvancedPanel({ threatIntelligence, knowledge }: Props) {
  const [expanded, setExpanded] = useState(false);

  // Merge all evidence, deduplicated by summary+type key
  const seen = new Set<string>();
  const allEvidence = [
    ...threatIntelligence.evidence,
    ...knowledge.evidence,
  ].filter(({ evidence }) => {
    const key = `${evidence.type}:${evidence.summary}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const hasMetadata =
    Object.keys(threatIntelligence.metadata).length > 0 ||
    Object.keys(knowledge.metadata).length > 0;

  return (
    <section
      className="bg-zinc-900/40 border border-dashed border-zinc-800/60 rounded-2xl overflow-hidden"
      aria-label="Advanced details"
    >
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-zinc-900/60 transition-colors"
        aria-expanded={expanded}
      >
        <span className="text-sm font-medium text-zinc-500">Advanced Details</span>
        <Chevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="px-5 pb-5 space-y-6 border-t border-zinc-800/50 pt-4">
          {/* All evidence */}
          {allEvidence.length > 0 && (
            <div>
              <h3 className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-3">
                All Evidence ({allEvidence.length})
              </h3>
              <div className="space-y-1.5">
                {allEvidence.map(({ evidence, sources }, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="shrink-0 mt-0.5 px-1.5 py-px rounded font-mono text-[9px] bg-zinc-800 text-zinc-500 uppercase whitespace-nowrap">
                      {evidence.type.replace(/_/g, " ")}
                    </span>
                    <span className="text-zinc-400 leading-relaxed flex-1 min-w-0 break-all">
                      {evidence.summary}
                    </span>
                    <span className="shrink-0 text-zinc-700 text-[10px] hidden sm:block">
                      {sources.join(", ")}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Provider metadata JSON */}
          {hasMetadata && (
            <div>
              <h3 className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-3">
                Provider Metadata
              </h3>
              <pre className="text-[11px] text-zinc-500 font-mono overflow-x-auto bg-zinc-800/40 rounded-xl p-4 leading-relaxed whitespace-pre-wrap break-all">
                {JSON.stringify(
                  {
                    ...(Object.keys(threatIntelligence.metadata).length > 0 && {
                      threat_intelligence: threatIntelligence.metadata,
                    }),
                    ...(Object.keys(knowledge.metadata).length > 0 && {
                      knowledge: knowledge.metadata,
                    }),
                  },
                  null,
                  2,
                )}
              </pre>
            </div>
          )}

          {allEvidence.length === 0 && !hasMetadata && (
            <p className="text-xs text-zinc-600">No detailed data available.</p>
          )}
        </div>
      )}
    </section>
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
      className={`text-zinc-500 transition-transform duration-150 ${expanded ? "rotate-180" : ""}`}
      aria-hidden
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
