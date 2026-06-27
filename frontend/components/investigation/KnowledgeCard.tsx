"use client";

import { useState } from "react";

import type { AttributedEvidence, ProviderSummary } from "@/lib/api";
import { statusDotClass, statusLabel, truncate } from "@/lib/investigation";

interface Props {
  provider: ProviderSummary;
  evidence: AttributedEvidence[];
  metadata: unknown;
}

export function KnowledgeCard({ provider, evidence, metadata }: Props) {
  const [expanded, setExpanded] = useState(false);

  const classification = evidence.find((e) => e.evidence.type === "classification");
  const categories = evidence.filter((e) => e.evidence.type === "category");
  const detection = evidence.find((e) => e.evidence.type === "detection");
  const mitigations = evidence.filter(
    (e) => e.evidence.type === "other" && e.evidence.summary.startsWith("Mitigation:"),
  );
  const otherEvidence = evidence.filter(
    (e) =>
      e.evidence.type !== "tag" &&
      e.evidence.type !== "classification" &&
      e.evidence.type !== "category" &&
      e.evidence.type !== "detection" &&
      !(e.evidence.type === "other" && e.evidence.summary.startsWith("Mitigation:")),
  );
  const tagEvidence = evidence.filter((e) => e.evidence.type === "tag");

  // Description lives in provider-namespaced metadata (e.g. metadata["description"])
  const meta = metadata as Record<string, unknown> | undefined;
  const description = meta?.description as string | undefined;

  const displayName = provider.provider_display_name ?? provider.provider;

  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-zinc-800/60 transition-colors"
        aria-expanded={expanded}
        aria-label={`${displayName} knowledge details`}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <span className={`shrink-0 w-2 h-2 rounded-full ${statusDotClass(provider.status)}`} aria-hidden />
          <span className="text-sm font-medium text-zinc-200 truncate">{displayName}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-[11px] text-zinc-500 hidden sm:block">
            {statusLabel(provider.status)}
          </span>
          <Chevron expanded={expanded} />
        </div>
      </button>

      {/* Collapsed preview */}
      {!expanded && (
        <div className="px-4 pb-3 space-y-2">
          {classification && (
            <p className="text-xs text-zinc-300 leading-relaxed">{classification.evidence.summary}</p>
          )}
          {categories.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {categories.slice(0, 4).map((c, i) => (
                <span
                  key={i}
                  className="px-2 py-0.5 rounded-md bg-zinc-700/60 border border-zinc-600/40 text-xs text-zinc-400"
                >
                  {c.evidence.value ?? c.evidence.summary.replace(/^[^:]+:\s*/, "")}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Expanded */}
      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-zinc-700/40 pt-3">
          {/* Classification */}
          {classification && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-1.5">
                Classification
              </p>
              <p className="text-sm text-zinc-200">{classification.evidence.summary}</p>
            </div>
          )}

          {/* Description */}
          {description && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-1.5">
                Description
              </p>
              <p className="text-xs text-zinc-400 leading-relaxed">{truncate(description, 500)}</p>
            </div>
          )}

          {/* Categories / Tactics */}
          {categories.length > 0 && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-2">Categories</p>
              <div className="flex flex-wrap gap-1.5">
                {categories.map((c, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 rounded-md bg-zinc-700/60 border border-zinc-600/40 text-xs text-zinc-300"
                  >
                    {c.evidence.value ?? c.evidence.summary.replace(/^[^:]+:\s*/, "")}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Detection guidance */}
          {detection && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-1.5">
                Detection Guidance
              </p>
              <p className="text-xs text-zinc-400 leading-relaxed">
                {truncate(detection.evidence.value ?? detection.evidence.summary, 400)}
              </p>
            </div>
          )}

          {/* Mitigations */}
          {mitigations.length > 0 && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-2">
                Mitigations ({mitigations.length})
              </p>
              <ul className="space-y-1">
                {mitigations.map((m, i) => (
                  <li key={i} className="text-xs text-zinc-400 leading-relaxed">
                    {m.evidence.summary.replace(/^Mitigation:\s*/, "")}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Other evidence */}
          {otherEvidence.length > 0 && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-2">
                Additional Findings
              </p>
              <div className="space-y-1.5">
                {otherEvidence.map((e, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="shrink-0 mt-0.5 px-1.5 py-px rounded font-mono text-[9px] bg-zinc-700/60 text-zinc-500 uppercase">
                      {e.evidence.type.replace(/_/g, " ")}
                    </span>
                    <span className="text-zinc-300 leading-relaxed">{e.evidence.summary}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Aliases / Tags */}
          {tagEvidence.length > 0 && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-2">Aliases</p>
              <div className="flex flex-wrap gap-1.5">
                {tagEvidence.map((e, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 rounded-md bg-zinc-700/50 border border-zinc-600/40 text-xs text-zinc-400"
                  >
                    {e.evidence.value ?? e.evidence.summary}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Error / not found notice */}
          {provider.error && (
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs">
              <p className="text-red-400">{provider.error.message}</p>
            </div>
          )}
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
      className={`text-zinc-500 transition-transform duration-150 ${expanded ? "rotate-180" : ""}`}
      aria-hidden
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
