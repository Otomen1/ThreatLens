import type { CorrelationSummary, InvestigationExposureSummary } from "@/lib/api";

interface Props {
  exposure: InvestigationExposureSummary | null;
  correlation: CorrelationSummary | null;
}

/** Additive context from downstream engines; never presents it as a new verdict. */
export function ContextSignalsCard({ exposure, correlation }: Props) {
  if (!exposure && !correlation) return null;

  const exposureHasData = Boolean(exposure?.statistics.total_findings || exposure?.statistics.total_assets);
  const exposureErrors = exposure?.findings.filter((finding) => finding.error || finding.status !== "ok") ?? [];

  return (
    <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-4" aria-label="Context signals">
      <div>
        <h2 className="text-sm font-semibold text-white">Context Signals</h2>
        <p className="text-xs text-zinc-500 mt-1">Additional exposure and correlation context. These signals do not change the assessment above.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {exposure && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-xs font-semibold text-zinc-200">Exposure</h3>
              <span className="text-[10px] text-zinc-500">{exposure.statistics.providers_queried} provider(s)</span>
            </div>
            <p className="text-sm text-zinc-300 mt-3">
              {exposureHasData ? `${exposure.statistics.total_assets} exposed asset(s) across ${exposure.statistics.total_findings} finding(s).` : "No exposure data was reported."}
            </p>
            {exposure.statistics.categories.length > 0 && (
              <p className="text-[11px] text-zinc-500 mt-2">{exposure.statistics.categories.join(" · ")}</p>
            )}
            {exposureErrors.length > 0 && (
              <p className="text-[11px] text-amber-400/80 mt-2">{exposureErrors.length} provider result(s) need attention.</p>
            )}
          </div>
        )}

        {correlation && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-xs font-semibold text-zinc-200">Correlations</h3>
              <span className="text-[10px] text-zinc-500">{correlation.statistics.rules_matched} rule(s) matched</span>
            </div>
            <p className="text-sm text-zinc-300 mt-3">
              {correlation.observations.length > 0 ? `${correlation.observations.length} higher-level observation(s) connect existing findings.` : "No cross-finding correlations were found."}
            </p>
            {correlation.observations.length > 0 && (
              <ul className="mt-3 space-y-2">
                {correlation.observations.slice(0, 3).map((observation) => (
                  <li key={observation.id} className="text-xs text-zinc-400">
                    <span className="text-zinc-200">{observation.title}</span>
                    {observation.summary && <span className="block text-zinc-600 mt-0.5">{observation.summary}</span>}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
