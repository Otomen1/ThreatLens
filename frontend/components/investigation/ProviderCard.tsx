"use client";

import { useState } from "react";

import type { AttributedEvidence, ProviderSummary } from "@/lib/api";
import {
  reputationClasses,
  reputationLabel,
  statusDotClass,
  statusLabel,
} from "@/lib/investigation";

interface Props {
  provider: ProviderSummary;
  evidence: AttributedEvidence[];
}

// Evidence types shown as inline pills in the preview (collapsed state)
const PREVIEW_SKIP = new Set(["tag", "classification", "pulse_match"]);

export function ProviderCard({ provider, evidence }: Props) {
  const [expanded, setExpanded] = useState(false);

  const previewItems = evidence.filter((e) => !PREVIEW_SKIP.has(e.evidence.type)).slice(0, 3);
  const nonTagEvidence = evidence.filter((e) => e.evidence.type !== "tag");
  const tagEvidence = evidence.filter((e) => e.evidence.type === "tag");

  const displayName = provider.provider_display_name ?? provider.provider;

  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl overflow-hidden">
      {/* Header row — always visible */}
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-zinc-800/60 transition-colors"
        aria-expanded={expanded}
        aria-label={`${displayName} provider details`}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <span
            className={`shrink-0 w-2 h-2 rounded-full ${statusDotClass(provider.status)}`}
            aria-hidden
          />
          <span className="text-sm font-medium text-zinc-200 truncate">{displayName}</span>
          {provider.reputation && (
            <span
              className={`shrink-0 px-2 py-0.5 rounded-md border text-[11px] font-semibold uppercase tracking-wide ${reputationClasses(provider.reputation.level)}`}
            >
              {reputationLabel(provider.reputation.level)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-[11px] text-zinc-500 hidden sm:block">
            {statusLabel(provider.status)}
          </span>
          <Chevron expanded={expanded} />
        </div>
      </button>

      {/* Collapsed preview */}
      {!expanded && previewItems.length > 0 && (
        <div className="px-4 pb-3 space-y-1">
          {previewItems.map((e, i) => (
            <p key={i} className="text-xs text-zinc-500 leading-relaxed">
              {e.evidence.summary}
            </p>
          ))}
        </div>
      )}

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-zinc-700/40 pt-3">
          {/* Reputation breakdown */}
          {provider.reputation && (
            <div className="space-y-1.5">
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider">Reputation</p>
              <div className="flex flex-wrap gap-2 text-xs text-zinc-400">
                {provider.reputation.score !== null && (
                  <span>Score: {provider.reputation.score}</span>
                )}
                {provider.reputation.malicious_count !== null &&
                  provider.reputation.total_count !== null && (
                    <span>
                      {provider.reputation.malicious_count}/{provider.reputation.total_count}{" "}
                      flagged
                    </span>
                  )}
                {provider.reputation.summary && <span>{provider.reputation.summary}</span>}
              </div>
            </div>
          )}

          {/* Evidence list */}
          {nonTagEvidence.length > 0 && (
            <div className="space-y-2">
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider">Findings</p>
              <div className="space-y-1.5">
                {nonTagEvidence.map((e, i) => (
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

          {/* Tags */}
          {tagEvidence.length > 0 && (
            <div>
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-2">Tags</p>
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

          {/* Error info */}
          {provider.error && (
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs">
              <p className="text-red-400">{provider.error.message}</p>
              {provider.error.detail && (
                <p className="text-red-400/60 mt-0.5">{provider.error.detail}</p>
              )}
            </div>
          )}

          {/* Not-found / unsupported notice */}
          {(provider.status === "not_found" || provider.status === "unsupported") &&
            !provider.error && (
              <p className="text-xs text-zinc-500">
                {provider.status === "not_found"
                  ? "No matching record found."
                  : "This entity type is not supported by this provider."}
              </p>
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
