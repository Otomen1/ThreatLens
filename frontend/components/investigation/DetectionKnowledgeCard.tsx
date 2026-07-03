"use client";

import { useEffect, useRef, useState } from "react";

import {
  recommendCommunityDetections,
  type CommunityRecommendation,
  type InvestigationSummary,
  type RuleMatch,
} from "@/lib/api";
import {
  communityRuleFilename,
  isRedistributable,
  licenseSupportLabel,
  matchTypeClass,
  matchTypeLabel,
  similarityClass,
} from "@/lib/knowledge";
import { detectionSeverityLabel } from "@/lib/detection";

interface Props {
  summary: InvestigationSummary;
}

/**
 * The Detection Knowledge panel — a downstream, read-only consumer that
 * recommends *community* detections resembling the investigation. It is kept
 * visually and structurally separate from the generated Detection Engineering
 * panel: these rules are authored elsewhere, carry their own provenance, and are
 * never merged with generated content. Collapsed by default; fetched lazily.
 */
export function DetectionKnowledgeCard({ summary }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CommunityRecommendation | null>(null);
  const [failed, setFailed] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    abortRef.current?.abort();
    setExpanded(false);
    setData(null);
    setFailed(false);
    setLoading(false);
  }, [summary]);

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
      setData(await recommendCommunityDetections(summary, controller.signal));
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }

  const count = data?.matches.length ?? 0;

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden"
      aria-label="Detection knowledge"
    >
      <button
        onClick={toggle}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-zinc-800/40 transition-colors"
        aria-expanded={expanded}
      >
        <LibraryIcon />
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-semibold text-white">Detection Knowledge</span>
          <span className="block text-[11px] text-zinc-500">
            Community detections that resemble this investigation · read-only, complementary
          </span>
        </span>
        {count > 0 && (
          <span className="text-[11px] font-mono text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5">
            {count}
          </span>
        )}
        <Chevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="px-5 pb-5 pt-1 border-t border-zinc-800">
          {loading && (
            <p className="text-sm text-zinc-400 animate-pulse pt-3">Searching the community library…</p>
          )}
          {!loading && failed && (
            <p className="text-sm text-zinc-400 pt-3">
              The community library could not be reached. The investigation above is unaffected.
            </p>
          )}
          {!loading && !failed && data && <RecommendationView data={data} />}
        </div>
      )}
    </section>
  );
}

function RecommendationView({ data }: { data: CommunityRecommendation }) {
  if (data.matches.length === 0) {
    return (
      <div className="space-y-4 pt-3">
        <div
          className="flex items-start gap-3 rounded-xl border border-zinc-700/60 bg-zinc-800/40 p-4"
          role="status"
        >
          <InfoIcon />
          <p className="text-sm text-zinc-400 leading-relaxed">
            No community detections matched this investigation. This is complementary context — the
            generated detections and the findings above are unaffected.
          </p>
        </div>
        <Footer data={data} />
      </div>
    );
  }

  return (
    <div className="space-y-3 pt-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-[11px] text-zinc-500 uppercase tracking-wider flex-1">
          Community Matches ({data.matches.length})
        </p>
        <Tally label="Exact" value={data.exact_count} />
        <Tally label="Partial" value={data.partial_count} />
        <Tally label="Related" value={data.related_count} />
      </div>
      <ul className="space-y-3">
        {data.matches.map((match) => (
          <li key={match.rule.id}>
            <MatchCard match={match} />
          </li>
        ))}
      </ul>
      <Footer data={data} />
    </div>
  );
}

/** One community rule match: provenance + similarity + optional rule body. */
function MatchCard({ match }: { match: RuleMatch }) {
  const { rule } = match;
  const canShow = isRedistributable(rule.license.support) && rule.content !== null;
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (!rule.content) return;
    try {
      await navigator.clipboard.writeText(rule.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — the rule text is visible below */
    }
  }

  function download() {
    if (!rule.content) return;
    const blob = new Blob([rule.content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = communityRuleFilename(rule);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-zinc-800">
        <Badge className={matchTypeClass(match.match_type)}>{matchTypeLabel(match.match_type)}</Badge>
        <span className="flex-1 min-w-0 text-sm font-medium text-zinc-200 truncate">{rule.name}</span>
        <span className={`text-xs font-mono ${similarityClass(match.similarity)}`}>
          {match.similarity}% sim
        </span>
        <span className="text-[11px] font-mono text-zinc-500">{match.coverage}% cov</span>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 px-4 py-3 text-[11px] sm:grid-cols-3">
        <Field label="Repository" value={rule.source.name} />
        <Field label="Language" value={rule.language} mono />
        <Field label="Severity" value={detectionSeverityLabel(rule.severity)} />
        <Field label="Author" value={rule.author.name} />
        <Field label="License" value={`${rule.license.spdx_id} · ${licenseSupportLabel(rule.license.support)}`} />
        <Field label="Updated" value={rule.version.updated ?? "—"} />
      </div>

      {(rule.mitre_techniques.length > 0 || match.shared_iocs.length > 0) && (
        <div className="flex flex-wrap items-center gap-1.5 px-4 pb-3">
          {rule.mitre_techniques.map((t) => (
            <Badge key={t} className="text-indigo-300 bg-indigo-500/10 border-indigo-500/30">
              {t}
            </Badge>
          ))}
          {match.shared_iocs.map((ioc) => (
            <Badge key={ioc} className="text-emerald-300 bg-emerald-500/10 border-emerald-500/30">
              {ioc}
            </Badge>
          ))}
        </div>
      )}

      {match.rationale && <p className="px-4 pb-3 text-[11px] text-zinc-500">{match.rationale}</p>}

      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-t border-zinc-800">
        <a
          href={rule.url}
          target="_blank"
          rel="noreferrer noopener"
          className="text-[11px] font-medium text-sky-400 hover:text-sky-300"
        >
          View rule ↗
        </a>
        {canShow ? (
          <>
            <IconButton label={copied ? "Copied" : "Copy"} onClick={copy} />
            <IconButton label="Download" onClick={download} />
          </>
        ) : (
          <span className="text-[10px] text-amber-400/80">
            Rule body withheld under {rule.license.spdx_id}; view at the source ↗
          </span>
        )}
      </div>

      {canShow && rule.content && (
        <pre className="mx-4 mb-4 overflow-x-auto rounded-lg bg-black/40 p-3 text-[11px] leading-relaxed text-zinc-300">
          <code className="font-mono whitespace-pre">{rule.content}</code>
        </pre>
      )}
    </div>
  );
}

function Footer({ data }: { data: CommunityRecommendation }) {
  return (
    <p className="text-[11px] text-zinc-600 border-t border-zinc-800 pt-3">
      Community Library v{data.library_version} ({data.sync_status}) · community rules are authored by
      third parties and shown with attribution and license. They are complementary to — never a
      replacement for — the generated detections and the findings above.
    </p>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <span className="block text-[9px] uppercase tracking-wider text-zinc-600">{label}</span>
      <span className={`block truncate text-zinc-300 ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

function Tally({ label, value }: { label: string; value: number }) {
  return (
    <span className="text-[10px] font-mono text-zinc-500">
      {value} {label.toLowerCase()}
    </span>
  );
}

function Badge({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <span className={`text-[10px] font-mono rounded border px-1.5 py-0.5 ${className ?? ""}`}>
      {children}
    </span>
  );
}

function IconButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="text-[10px] font-medium text-zinc-400 hover:text-zinc-200 bg-zinc-800/80 hover:bg-zinc-700 border border-zinc-700 rounded px-2 py-1 transition-colors"
    >
      {label}
    </button>
  );
}

function LibraryIcon() {
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
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
    </svg>
  );
}

function InfoIcon() {
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
      className="mt-0.5 shrink-0 text-zinc-500"
      aria-hidden
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
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
