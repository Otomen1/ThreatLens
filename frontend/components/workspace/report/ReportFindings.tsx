// Findings (Phase 8.4): every existing Finding, fully expanded — a printed
// report has no collapsed state to click open. Every field shown (severity,
// title, categories, rule ids, confidence, evidence, relationships, sources)
// is copied verbatim from the existing Finding contract; nothing is
// generated or recomputed.

import type { Finding, WeightedEvidence } from "@/lib/api";
import {
  confidenceBandClasses,
  confidenceBandLabel,
  formatRelationship,
  formatTargetType,
  severityClasses,
  severityLabel,
  titleCase,
} from "@/lib/investigation";

export function ReportFindings({ findings }: { findings: Finding[] }) {
  return (
    <section className="space-y-3" aria-label="Findings">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600">
        Findings
        <span className="ml-2 font-normal normal-case text-zinc-600 print:text-zinc-500">
          ({findings.length})
        </span>
      </h2>
      {findings.length === 0 ? (
        <p className="text-sm text-zinc-500 print:text-zinc-600">
          No findings were generated for this entity by the reasoning engine.
        </p>
      ) : (
        <div className="space-y-3">
          {findings.map((finding) => (
            <FindingBlock key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </section>
  );
}

function FindingBlock({ finding }: { finding: Finding }) {
  return (
    <div className="border border-zinc-800 print:border-zinc-300 rounded-lg p-3 print:break-inside-avoid">
      <div className="flex flex-wrap items-center gap-2 mb-1.5">
        <span
          className={`shrink-0 px-2 py-0.5 rounded-md border print:border-zinc-400 print:bg-white text-[11px] font-medium ${severityClasses(finding.severity)}`}
        >
          {severityLabel(finding.severity)}
        </span>
        <span className="flex-1 min-w-0 text-sm font-medium text-zinc-100 print:text-black break-words">
          {finding.title}
        </span>
        <span
          className={`shrink-0 px-1.5 py-0.5 rounded-md border print:border-zinc-400 print:bg-white text-[11px] ${confidenceBandClasses(finding.confidence.band)}`}
        >
          {confidenceBandLabel(finding.confidence.band)} · {finding.confidence.score}
        </span>
        <span className="shrink-0 px-1.5 py-0.5 rounded bg-zinc-800 print:bg-white border border-zinc-700/60 print:border-zinc-400 text-[11px] text-zinc-400 print:text-zinc-700 font-mono">
          P{finding.priority}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-1.5 mb-2 text-[10px]">
        {finding.categories.map((cat) => (
          <span
            key={cat}
            className="px-1.5 py-0.5 rounded bg-zinc-800/70 print:bg-white border border-zinc-700/50 print:border-zinc-300 text-zinc-400 print:text-zinc-700"
          >
            {titleCase(cat)}
          </span>
        ))}
        {finding.rule_ids.map((id) => (
          <span
            key={id}
            className="px-1.5 py-0.5 rounded bg-zinc-800 print:bg-white border border-zinc-700/60 print:border-zinc-300 font-mono text-zinc-500 print:text-zinc-600"
          >
            {id}
          </span>
        ))}
        <span className="text-zinc-600 print:text-zinc-500 font-mono ml-auto">
          {finding.subject_type}:{finding.subject_value}
        </span>
      </div>

      {finding.rationale && (
        <p className="text-xs text-zinc-400 print:text-zinc-700 leading-relaxed mb-2">
          {finding.rationale}
        </p>
      )}

      {finding.evidence.length > 0 && (
        <div className="mb-2">
          <p className="text-[10px] uppercase tracking-wider text-zinc-600 print:text-zinc-500 mb-1">
            Evidence ({finding.evidence.length})
          </p>
          <ul className="space-y-1">
            {finding.evidence.map((item, i) => (
              <EvidenceLine key={i} item={item} />
            ))}
          </ul>
        </div>
      )}

      {finding.relationships.length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider text-zinc-600 print:text-zinc-500 mb-1">
            Relationships ({finding.relationships.length})
          </p>
          <ul className="space-y-0.5">
            {finding.relationships.map((r, i) => (
              <li key={i} className="text-xs text-zinc-400 print:text-zinc-700">
                <span className="capitalize">{formatRelationship(r.relationship.relationship)}</span>{" "}
                <span className="text-zinc-600 print:text-zinc-500">
                  {formatTargetType(r.relationship.target_type)}
                </span>{" "}
                <span className="font-mono text-zinc-300 print:text-black break-all">
                  {r.relationship.target_value}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function EvidenceLine({ item }: { item: WeightedEvidence }) {
  const ev = item.evidence.evidence;
  return (
    <li className="text-xs text-zinc-400 print:text-zinc-700 leading-relaxed">
      <span className="text-zinc-300 print:text-black">{ev.summary}</span>
      <span className="ml-1.5 text-[10px] text-zinc-600 print:text-zinc-500">
        {item.dimension} · {item.evidence.sources.join(", ")}
      </span>
    </li>
  );
}
