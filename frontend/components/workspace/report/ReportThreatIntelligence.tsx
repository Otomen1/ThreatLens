// Threat Intelligence (Phase 8.4): a provider-attribution view — which
// existing evidence/relationship sources contributed to this investigation,
// and to which findings. A complementary lens to the Findings section
// above (which is finding-first); this is source-first. Every count is a
// tally over already-existing `AttributedEvidence`/`AttributedRelationship`
// `sources` fields — nothing is invented, and no per-provider status or
// reputation is shown here because that (`ProviderSummary`) is not part of
// a saved WorkspaceInvestigation; see the architecture doc's "Known
// limitations".

import type { Finding } from "@/lib/api";

export interface ProviderContribution {
  provider: string;
  evidenceCount: number;
  relationshipCount: number;
  findingTitles: string[];
}

/** Tally evidence/relationship contributions per provider, across every
 * finding's existing `sources`. Sorted alphabetically by provider name for
 * a deterministic, reproducible report. */
export function summarizeProviders(findings: Finding[]): ProviderContribution[] {
  const byProvider = new Map<
    string,
    { evidenceCount: number; relationshipCount: number; findingTitles: Set<string> }
  >();

  const bump = (
    source: string,
    finding: Finding,
    field: "evidenceCount" | "relationshipCount",
  ) => {
    const entry = byProvider.get(source) ?? {
      evidenceCount: 0,
      relationshipCount: 0,
      findingTitles: new Set<string>(),
    };
    entry[field] += 1;
    entry.findingTitles.add(finding.title);
    byProvider.set(source, entry);
  };

  for (const finding of findings) {
    for (const item of finding.evidence) {
      for (const source of item.evidence.sources) bump(source, finding, "evidenceCount");
    }
    for (const rel of finding.relationships) {
      for (const source of rel.sources) bump(source, finding, "relationshipCount");
    }
  }

  return [...byProvider.entries()]
    .map(([provider, v]) => ({
      provider,
      evidenceCount: v.evidenceCount,
      relationshipCount: v.relationshipCount,
      findingTitles: [...v.findingTitles],
    }))
    .sort((a, b) => a.provider.localeCompare(b.provider));
}

export function ReportThreatIntelligence({ findings }: { findings: Finding[] }) {
  const providers = summarizeProviders(findings);

  return (
    <section className="print:break-inside-avoid" aria-label="Threat intelligence">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600 mb-2">
        Threat Intelligence
      </h2>
      {providers.length === 0 ? (
        <p className="text-sm text-zinc-500 print:text-zinc-600">
          No attributed evidence or relationship sources are present on this investigation.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-zinc-500 print:text-zinc-600 border-b border-zinc-800 print:border-zinc-300">
                <th className="py-1 pr-3 font-medium">Provider</th>
                <th className="py-1 pr-3 font-medium">Evidence</th>
                <th className="py-1 pr-3 font-medium">Relationships</th>
                <th className="py-1 font-medium">Contributed To</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((p) => (
                <tr
                  key={p.provider}
                  className="border-b border-zinc-800/60 print:border-zinc-200 align-top"
                >
                  <td className="py-1.5 pr-3 text-zinc-200 print:text-black whitespace-nowrap">
                    {p.provider}
                  </td>
                  <td className="py-1.5 pr-3 text-zinc-400 print:text-zinc-700 font-mono">
                    {p.evidenceCount}
                  </td>
                  <td className="py-1.5 pr-3 text-zinc-400 print:text-zinc-700 font-mono">
                    {p.relationshipCount}
                  </td>
                  <td className="py-1.5 text-zinc-400 print:text-zinc-700">
                    {p.findingTitles.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
