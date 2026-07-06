"use client";

import { useState } from "react";

import type { ExposureFinding } from "@/lib/api";

const STATUS_DOT: Record<string, string> = {
  ok: "bg-emerald-400",
  not_found: "bg-zinc-600",
  unsupported: "bg-zinc-600",
  error: "bg-red-400",
  timeout: "bg-red-400",
  rate_limited: "bg-amber-400",
  unauthorized: "bg-amber-400",
};

const STATUS_LABEL: Record<string, string> = {
  ok: "OK",
  not_found: "Not Found",
  unsupported: "Unsupported",
  error: "Error",
  timeout: "Timeout",
  rate_limited: "Rate Limited",
  unauthorized: "Unauthorized",
};

interface Props {
  finding: ExposureFinding;
}

export function ExposureFindingCard({ finding }: Props) {
  const [expanded, setExpanded] = useState(finding.status === "ok");
  const displayName = finding.provider_display_name ?? finding.provider;

  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-zinc-800/60 transition-colors"
        aria-expanded={expanded}
        aria-label={`${displayName} exposure details`}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <span
            className={`shrink-0 w-2 h-2 rounded-full ${STATUS_DOT[finding.status] ?? "bg-zinc-600"}`}
            aria-hidden
          />
          <span className="text-sm font-medium text-zinc-200 truncate">{displayName}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-[11px] text-zinc-500 hidden sm:block">
            {STATUS_LABEL[finding.status] ?? finding.status}
          </span>
          <Chevron expanded={expanded} />
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-zinc-700/40 pt-3">
          {finding.summary && <p className="text-xs text-zinc-400">{finding.summary}</p>}

          {finding.assets.length > 0 && (
            <div className="space-y-2">
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider">
                Assets ({finding.assets.length})
              </p>
              <div className="space-y-1.5">
                {finding.assets.map((asset, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="shrink-0 mt-0.5 px-1.5 py-px rounded font-mono text-[9px] bg-zinc-700/60 text-zinc-500 uppercase">
                      {asset.asset_type.replace(/_/g, " ")}
                    </span>
                    <span className="text-zinc-300 leading-relaxed">
                      {asset.value}
                      {Object.keys(asset.attributes).length > 0 && (
                        <span className="text-zinc-500">
                          {" — "}
                          {Object.entries(asset.attributes)
                            .map(([key, value]) => `${key}: ${value}`)
                            .join(", ")}
                        </span>
                      )}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {finding.evidence.length > 0 && (
            <div className="space-y-2">
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider">Evidence</p>
              <div className="space-y-1.5">
                {finding.evidence.map((item, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="shrink-0 mt-0.5 px-1.5 py-px rounded font-mono text-[9px] bg-zinc-700/60 text-zinc-500 uppercase">
                      {item.type.replace(/_/g, " ")}
                    </span>
                    <span className="text-zinc-300 leading-relaxed">{item.summary}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {finding.references.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[11px] text-zinc-500 uppercase tracking-wider">References</p>
              {finding.references.map((ref, i) => (
                <a
                  key={i}
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block text-xs text-zinc-400 hover:text-zinc-200 transition-colors truncate"
                >
                  {ref.title} ↗
                </a>
              ))}
            </div>
          )}

          {finding.error && (
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs">
              <p className="text-red-400">{finding.error.message}</p>
              {finding.error.detail && (
                <p className="text-red-400/60 mt-0.5">{finding.error.detail}</p>
              )}
            </div>
          )}

          {(finding.status === "not_found" || finding.status === "unsupported") &&
            !finding.error && (
              <p className="text-xs text-zinc-500">
                {finding.status === "not_found"
                  ? "No exposure data found for this entity."
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
