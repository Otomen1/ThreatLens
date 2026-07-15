// Recommendations (Phase 8.4): the existing recommendation rollup, fully
// expanded, with each recommendation's `finding_ids` shown directly for
// traceability back to the findings section above — a printed report has no
// click-to-expand interaction.

import type { Recommendation } from "@/lib/api";
import { recommendationCategoryClasses, titleCase } from "@/lib/investigation";

export function ReportRecommendations({
  recommendations,
}: {
  recommendations: Recommendation[];
}) {
  return (
    <section className="print:break-inside-avoid" aria-label="Recommendations">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600 mb-2">
        Recommendations
        <span className="ml-2 font-normal normal-case text-zinc-600 print:text-zinc-500">
          ({recommendations.length})
        </span>
      </h2>
      {recommendations.length === 0 ? (
        <p className="text-sm text-zinc-500 print:text-zinc-600">
          No recommendations were derived for this investigation.
        </p>
      ) : (
        <div className="space-y-2">
          {recommendations.map((rec, i) => (
            <div
              key={`${rec.action}:${rec.target_value}:${i}`}
              className="border border-zinc-800 print:border-zinc-300 rounded-lg p-2.5 print:break-inside-avoid"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`shrink-0 px-2 py-0.5 rounded-md border print:border-zinc-400 print:bg-white text-[11px] font-medium capitalize ${recommendationCategoryClasses(rec.category)}`}
                >
                  {rec.category}
                </span>
                <span className="flex-1 min-w-0 text-sm text-zinc-200 print:text-black">
                  {titleCase(rec.action)}
                </span>
                <span className="shrink-0 px-1.5 py-0.5 rounded bg-zinc-800 print:bg-white border border-zinc-700/60 print:border-zinc-400 text-[11px] text-zinc-400 print:text-zinc-700 font-mono">
                  P{rec.priority}
                </span>
              </div>
              <p className="text-xs text-zinc-400 print:text-zinc-700 leading-relaxed mt-1.5">
                {rec.rationale}
              </p>
              <p className="text-[10px] text-zinc-600 print:text-zinc-500 font-mono mt-1">
                Target: {rec.target_type}:{rec.target_value} · Rule: {rec.rule_id}
              </p>
              {rec.finding_ids.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
                  <span className="text-[10px] uppercase tracking-wider text-zinc-600 print:text-zinc-500">
                    From
                  </span>
                  {rec.finding_ids.map((id) => (
                    <span
                      key={id}
                      className="px-1.5 py-0.5 rounded bg-zinc-800 print:bg-white border border-zinc-700/60 print:border-zinc-300 text-[10px] font-mono text-zinc-500 print:text-zinc-600"
                    >
                      {id}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
