// Executive Assessment (Phase 8.4): the same deterministic fields
// InvestigationSummaryCard already shows on the interactive workspace page —
// posture, overall confidence, finding/recommendation counts, engine
// version — reformatted for print. No prose summary is generated; there is
// none in the saved record to show.

import type { InvestigationSummary } from "@/lib/api";
import {
  confidenceBandClasses,
  confidenceBandLabel,
  severityClasses,
  severityLabel,
} from "@/lib/investigation";

export function ReportAssessment({ summary }: { summary: InvestigationSummary }) {
  const { posture, overall_confidence, engine_version, findings, recommendations } = summary;

  return (
    <section className="print:break-inside-avoid" aria-label="Executive assessment">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600 mb-2">
        Executive Assessment
      </h2>
      <div className="flex flex-wrap items-center gap-2">
        <Badge label="Posture" value={severityLabel(posture)} className={severityClasses(posture)} />
        <Badge
          label="Confidence"
          value={`${confidenceBandLabel(overall_confidence.band)} · ${overall_confidence.score}`}
          className={confidenceBandClasses(overall_confidence.band)}
        />
        <CountBadge label="Findings" count={findings.length} />
        <CountBadge label="Recommendations" count={recommendations.length} />
        <span className="text-[11px] text-zinc-600 print:text-zinc-500 ml-auto">
          Reasoning engine {engine_version}
        </span>
      </div>
    </section>
  );
}

function Badge({ label, value, className }: { label: string; value: string; className: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border print:border-zinc-400 print:bg-white text-xs font-medium ${className}`}
    >
      <span className="text-[10px] uppercase tracking-wider opacity-70">{label}</span>
      {value}
    </span>
  );
}

function CountBadge({ label, count }: { label: string; count: number }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-zinc-700/60 print:border-zinc-400 bg-zinc-800/40 print:bg-white text-xs text-zinc-300 print:text-black">
      <span className="text-[10px] uppercase tracking-wider text-zinc-500 print:text-zinc-600">
        {label}
      </span>
      {count}
    </span>
  );
}
