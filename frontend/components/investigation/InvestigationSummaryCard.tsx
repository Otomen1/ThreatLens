import type { InvestigationSummary } from "@/lib/api";
import {
  confidenceBandClasses,
  confidenceBandLabel,
  severityClasses,
  severityLabel,
} from "@/lib/investigation";

interface Props {
  summary: InvestigationSummary;
}

/**
 * The reasoning headline: overall posture, overall confidence, engine version,
 * and finding/recommendation counts — concise badges, no raw JSON.
 */
export function InvestigationSummaryCard({ summary }: Props) {
  const { posture, overall_confidence, engine_version, findings, recommendations } = summary;

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
      aria-label="Investigation assessment"
    >
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-white">Investigation Assessment</h2>
        <span className="text-[11px] text-zinc-600">engine {engine_version}</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Badge
          label="Posture"
          value={severityLabel(posture)}
          className={severityClasses(posture)}
        />
        <Badge
          label="Confidence"
          value={`${confidenceBandLabel(overall_confidence.band)} · ${overall_confidence.score}`}
          className={confidenceBandClasses(overall_confidence.band)}
        />
        <CountBadge label="Findings" count={findings.length} />
        <CountBadge label="Recommendations" count={recommendations.length} />
      </div>
    </section>
  );
}

function Badge({
  label,
  value,
  className,
}: {
  label: string;
  value: string;
  className: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-medium ${className}`}
    >
      <span className="text-[10px] uppercase tracking-wider opacity-60">{label}</span>
      {value}
    </span>
  );
}

function CountBadge({ label, count }: { label: string; count: number }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-zinc-700/60 bg-zinc-800/40 text-xs text-zinc-300">
      <span className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</span>
      {count}
    </span>
  );
}
