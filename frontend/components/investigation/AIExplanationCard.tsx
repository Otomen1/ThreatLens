"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";

import { explain, type AIExplanation, type InvestigationSummary } from "@/lib/api";
import { titleCase } from "@/lib/investigation";

interface Props {
  summary: InvestigationSummary;
}

/**
 * The AI Explanation card — a downstream, optional consumer of the deterministic
 * summary. Collapsed by default; the explanation is fetched lazily on first
 * expand so no model is called unless an analyst asks. A disabled/unavailable
 * provider (or an unreachable backend) renders as a friendly note, never an
 * error — the deterministic investigation above is always authoritative.
 */
export function AIExplanationCard({ summary }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AIExplanation | null>(null);
  const [failed, setFailed] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // Reset when a new investigation arrives (the summary identity changes).
  useEffect(() => {
    abortRef.current?.abort();
    setExpanded(false);
    setData(null);
    setFailed(false);
    setLoading(false);
  }, [summary]);

  // Abort any in-flight request on unmount.
  useEffect(() => () => abortRef.current?.abort(), []);

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (!next || data !== null || loading) return;

    setLoading(true);
    setFailed(false);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      setData(await explain(summary, controller.signal));
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }

  const titleById = new Map(summary.findings.map((f) => [f.id, f.title]));

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden"
      aria-label="AI explanation"
    >
      <button
        onClick={toggle}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-zinc-800/40 transition-colors"
        aria-expanded={expanded}
      >
        <SparkIcon />
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-semibold text-white">AI Explanation</span>
          <span className="block text-[11px] text-zinc-500">
            Plain-language narration of the findings above · optional, advisory
          </span>
        </span>
        <Chevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="px-5 pb-5 pt-1 border-t border-zinc-800">
          {loading && <p className="text-sm text-zinc-400 animate-pulse">Generating explanation…</p>}
          {!loading && (failed || (data && data.status !== "ok")) && (
            <Unavailable message={!failed && data ? data.message : undefined} />
          )}
          {!loading && !failed && data && data.status === "ok" && (
            <Explanation data={data} titleById={titleById} />
          )}
        </div>
      )}
    </section>
  );
}

function Explanation({
  data,
  titleById,
}: {
  data: AIExplanation;
  titleById: Map<string, string>;
}) {
  return (
    <div className="space-y-4 pt-3">
      {data.executive_summary && (
        <Block label="Executive Summary">
          <p className="text-sm text-zinc-300 leading-relaxed">{data.executive_summary}</p>
        </Block>
      )}

      {data.technical_summary && (
        <Block label="Technical Summary">
          <p className="text-sm text-zinc-400 leading-relaxed">{data.technical_summary}</p>
        </Block>
      )}

      {data.finding_explanations.length > 0 && (
        <Block label={`Finding Explanations (${data.finding_explanations.length})`}>
          <ul className="space-y-2">
            {data.finding_explanations.map((fe) => (
              <li key={fe.finding_id} className="text-sm">
                <span className="text-zinc-200">{titleById.get(fe.finding_id) ?? fe.finding_id}</span>
                <span className="ml-2 text-[10px] font-mono text-zinc-600">{fe.finding_id}</span>
                <p className="text-zinc-400 leading-relaxed mt-0.5">{fe.explanation}</p>
              </li>
            ))}
          </ul>
        </Block>
      )}

      {data.recommendation_explanations.length > 0 && (
        <Block label={`Recommendation Explanations (${data.recommendation_explanations.length})`}>
          <ul className="space-y-2">
            {data.recommendation_explanations.map((re, i) => (
              <li key={`${re.action}:${re.target_value}:${i}`} className="text-sm">
                <span className="text-zinc-200">{titleCase(re.action)}</span>
                <span className="ml-2 text-[11px] font-mono text-zinc-500 break-all">
                  {re.target_value}
                </span>
                <p className="text-zinc-400 leading-relaxed mt-0.5">{re.explanation}</p>
              </li>
            ))}
          </ul>
        </Block>
      )}

      {data.limitations.length > 0 && (
        <Block label="Limitations">
          <ul className="list-disc list-inside space-y-1">
            {data.limitations.map((limitation, i) => (
              <li key={i} className="text-xs text-zinc-500 leading-relaxed">
                {limitation}
              </li>
            ))}
          </ul>
        </Block>
      )}

      <p className="text-[11px] text-zinc-600 border-t border-zinc-800 pt-3">
        Generated by {data.provider}
        {data.model ? ` · ${data.model}` : ""}. AI narration is advisory; the deterministic findings
        and recommendations above are authoritative.
      </p>
    </div>
  );
}

function Unavailable({ message }: { message?: string }) {
  return (
    <div className="pt-3">
      <p className="text-sm text-zinc-400">AI explanation unavailable.</p>
      {message && <p className="text-xs text-zinc-600 mt-1 leading-relaxed">{message}</p>}
      <p className="text-xs text-zinc-600 mt-2 leading-relaxed">
        The deterministic investigation above is complete and unaffected.
      </p>
    </div>
  );
}

function Block({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="text-[11px] text-zinc-500 uppercase tracking-wider mb-1.5">{label}</p>
      {children}
    </div>
  );
}

function SparkIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="shrink-0 text-zinc-400"
      aria-hidden
    >
      <path d="M12 3v3m0 12v3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1M3 12h3m12 0h3M5.6 18.4l2.1-2.1m8.6-8.6 2.1-2.1" />
    </svg>
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
