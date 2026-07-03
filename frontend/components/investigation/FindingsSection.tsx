"use client";

import { type ReactNode, useState } from "react";

import type { Finding, WeightedEvidence } from "@/lib/api";
import {
  confidenceBandClasses,
  confidenceBandLabel,
  formatRelationship,
  formatTargetType,
  recommendationCategoryClasses,
  severityClasses,
  severityLabel,
  titleCase,
} from "@/lib/investigation";

import { ConfidenceBreakdown } from "./ConfidenceBreakdown";

interface Props {
  findings: Finding[];
}

/**
 * Findings — the primary analyst surface. Each finding is a collapsed card whose
 * header carries severity / priority / confidence / category / subject, and
 * whose expansion reveals the reasoning: rule provenance, confidence breakdown,
 * supporting evidence (with attribution), relationships, and recommendations.
 */
export function FindingsSection({ findings }: Props) {
  return (
    <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5" aria-label="Findings">
      <h2 className="text-sm font-semibold text-white mb-3">
        Findings
        <span className="ml-2 text-xs font-normal text-zinc-500">({findings.length})</span>
      </h2>
      {findings.length === 0 ? (
        <p className="text-sm text-zinc-500">
          No findings were generated for this entity by the reasoning engine.
        </p>
      ) : (
        <div className="space-y-2">
          {findings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </section>
  );
}

/** A single finding's collapsed card (rationale, confidence, evidence,
 * relationships, recommendations). Exported for reuse — e.g. the Detection
 * Engineering panel's Findings tab renders the same card for linked findings. */
export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl overflow-hidden">
      {/* Header (collapsed view) */}
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-2.5 px-3 py-2.5 text-left hover:bg-zinc-800/60 transition-colors"
        aria-expanded={expanded}
      >
        <span
          className={`shrink-0 px-2 py-0.5 rounded-md border text-[11px] font-medium ${severityClasses(finding.severity)}`}
        >
          {severityLabel(finding.severity)}
        </span>
        <span className="flex-1 min-w-0 text-sm text-zinc-200 truncate">{finding.title}</span>
        <span
          className={`shrink-0 px-1.5 py-0.5 rounded-md border text-[11px] hidden sm:inline ${confidenceBandClasses(finding.confidence.band)}`}
        >
          {confidenceBandLabel(finding.confidence.band)}
        </span>
        <span className="shrink-0 px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700/60 text-[11px] text-zinc-400 font-mono">
          P{finding.priority}
        </span>
        <Chevron expanded={expanded} />
      </button>

      {/* Collapsed preview: categories + subject */}
      {!expanded && (
        <div className="px-3 pb-2.5 flex flex-wrap items-center gap-1.5">
          {finding.categories.map((cat) => (
            <span
              key={cat}
              className="px-1.5 py-0.5 rounded bg-zinc-700/50 border border-zinc-600/40 text-[10px] text-zinc-400 capitalize"
            >
              {titleCase(cat)}
            </span>
          ))}
          <span className="text-[11px] text-zinc-600 font-mono ml-auto truncate">
            {finding.subject_value}
          </span>
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="px-3 pb-4 pt-1 border-t border-zinc-700/40 space-y-4">
          {finding.rationale && (
            <p className="text-xs text-zinc-400 leading-relaxed">{finding.rationale}</p>
          )}

          {/* Categories + subject + rule provenance */}
          <div className="flex flex-wrap items-center gap-1.5">
            {finding.categories.map((cat) => (
              <span
                key={cat}
                className="px-1.5 py-0.5 rounded bg-zinc-700/50 border border-zinc-600/40 text-[10px] text-zinc-400"
              >
                {titleCase(cat)}
              </span>
            ))}
            {finding.rule_ids.map((id) => (
              <span
                key={id}
                className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700/60 text-[10px] font-mono text-zinc-500"
              >
                {id}
              </span>
            ))}
          </div>

          <Block label="Confidence">
            <ConfidenceBreakdown confidence={finding.confidence} />
          </Block>

          {finding.evidence.length > 0 && (
            <Block label={`Supporting Evidence (${finding.evidence.length})`}>
              <div className="space-y-1.5">
                {finding.evidence.map((item, i) => (
                  <EvidenceRow key={i} item={item} />
                ))}
              </div>
            </Block>
          )}

          {finding.relationships.length > 0 && (
            <Block label={`Relationships (${finding.relationships.length})`}>
              <ul className="space-y-1">
                {finding.relationships.map((r, i) => (
                  <li key={i} className="text-xs text-zinc-400">
                    <span className="capitalize">
                      {formatRelationship(r.relationship.relationship)}
                    </span>{" "}
                    <span className="text-zinc-600">
                      {formatTargetType(r.relationship.target_type)}
                    </span>{" "}
                    <span className="font-mono text-zinc-300 break-all">
                      {r.relationship.target_value}
                    </span>
                  </li>
                ))}
              </ul>
            </Block>
          )}

          {finding.recommendations.length > 0 && (
            <Block label={`Recommendations (${finding.recommendations.length})`}>
              <ul className="space-y-1.5">
                {finding.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs">
                    <span
                      className={`shrink-0 px-1.5 py-0.5 rounded-md border text-[10px] capitalize ${recommendationCategoryClasses(rec.category)}`}
                    >
                      {rec.category}
                    </span>
                    <span className="text-zinc-300 leading-relaxed">
                      <span className="text-zinc-200">{titleCase(rec.action)}</span>
                      {" — "}
                      {rec.rationale}
                    </span>
                  </li>
                ))}
              </ul>
            </Block>
          )}
        </div>
      )}
    </div>
  );
}

function EvidenceRow({ item }: { item: WeightedEvidence }) {
  const ev = item.evidence.evidence;
  return (
    <div className="flex items-start gap-2 text-xs">
      <span
        className={`shrink-0 mt-0.5 px-1.5 py-px rounded text-[9px] uppercase ${polarityClasses(item.polarity)}`}
      >
        {item.polarity}
      </span>
      <div className="min-w-0">
        <span className="text-zinc-300 leading-relaxed">{ev.summary}</span>
        <span className="ml-2 text-[10px] text-zinc-600">
          {item.dimension} · {item.evidence.sources.join(", ")}
        </span>
      </div>
    </div>
  );
}

function polarityClasses(polarity: string): string {
  switch (polarity) {
    case "supporting":
      return "bg-emerald-500/10 text-emerald-400";
    case "contradicting":
      return "bg-red-500/10 text-red-400";
    default:
      return "bg-zinc-700/60 text-zinc-500";
  }
}

function Block({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-1.5">{label}</p>
      {children}
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
