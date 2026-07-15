// Correlation (Phase 8.4): every existing CorrelationObservation, verbatim.
// Absent entirely on most saved investigations today (Correlation isn't
// wired into /investigate yet) — a clear empty state, not an error, exactly
// like the interactive workspace page's own handling.

import type { CorrelationSummary } from "@/lib/api";
import { titleCase } from "@/lib/investigation";

export function ReportCorrelation({ correlation }: { correlation: CorrelationSummary | null }) {
  const observations = correlation?.observations ?? [];

  return (
    <section className="print:break-inside-avoid" aria-label="Correlation">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600 mb-2">
        Correlation
        <span className="ml-2 font-normal normal-case text-zinc-600 print:text-zinc-500">
          ({observations.length})
        </span>
      </h2>
      {observations.length === 0 ? (
        <p className="text-sm text-zinc-500 print:text-zinc-600">
          No correlation observations are attached to this investigation.
        </p>
      ) : (
        <div className="space-y-2">
          {observations.map((obs) => (
            <div
              key={obs.id}
              className="border border-zinc-800 print:border-zinc-300 rounded-lg p-2.5 print:break-inside-avoid"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-1.5 py-0.5 rounded bg-zinc-800/70 print:bg-white border border-zinc-700/50 print:border-zinc-300 text-[10px] text-zinc-400 print:text-zinc-700">
                  {titleCase(obs.category)}
                </span>
                <span className="flex-1 min-w-0 text-sm text-zinc-200 print:text-black">
                  {obs.title}
                </span>
                <span className="text-[10px] font-mono text-zinc-600 print:text-zinc-500">
                  {obs.id}
                </span>
              </div>
              {obs.summary && (
                <p className="text-xs text-zinc-400 print:text-zinc-700 leading-relaxed mt-1">
                  {obs.summary}
                </p>
              )}
              <p className="text-[10px] text-zinc-600 print:text-zinc-500 font-mono mt-1">
                Subject: {obs.subject_type}:{obs.subject_value} · Rule: {obs.rule_id}
              </p>

              {obs.evidence.length > 0 && (
                <ul className="mt-1.5 space-y-0.5">
                  {obs.evidence.map((e, i) => (
                    <li key={i} className="text-xs text-zinc-400 print:text-zinc-700">
                      <span className="font-mono text-zinc-500 print:text-zinc-600">
                        {e.finding_id}
                      </span>{" "}
                      — {e.summary || titleCase(e.matched_category)}
                    </li>
                  ))}
                </ul>
              )}

              {obs.relationships.length > 0 && (
                <ul className="mt-1.5 space-y-0.5">
                  {obs.relationships.map((r, i) => (
                    <li key={i} className="text-xs text-zinc-400 print:text-zinc-700">
                      <span className="font-mono text-zinc-300 print:text-black">
                        {r.source_finding_id}
                      </span>{" "}
                      <span className="capitalize">{titleCase(r.type)}</span>{" "}
                      <span className="font-mono text-zinc-300 print:text-black">
                        {r.target_finding_id}
                      </span>
                      {r.description && (
                        <span className="text-zinc-600 print:text-zinc-500"> — {r.description}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
