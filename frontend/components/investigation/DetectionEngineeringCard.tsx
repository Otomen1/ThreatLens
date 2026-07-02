"use client";

import { useEffect, useRef, useState } from "react";

import {
  generateDetections,
  type DetectionArtifact,
  type DetectionPackage,
  type InvestigationSummary,
} from "@/lib/api";

interface Props {
  summary: InvestigationSummary;
}

/**
 * The Detection Engineering panel — a downstream, optional consumer of the
 * deterministic summary. Collapsed by default; the DetectionPackage is fetched
 * lazily on first expand. In this phase the framework generates no artifacts, so
 * the panel shows a friendly empty state. The UI already understands a
 * fully-populated DetectionPackage; rule rendering arrives with the generators.
 */
export function DetectionEngineeringCard({ summary }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<DetectionPackage | null>(null);
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
      setData(await generateDetections(summary, controller.signal));
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden"
      aria-label="Detection engineering"
    >
      <button
        onClick={toggle}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-zinc-800/40 transition-colors"
        aria-expanded={expanded}
      >
        <ShieldIcon />
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-semibold text-white">Detection Engineering</span>
          <span className="block text-[11px] text-zinc-500">
            Reusable detection content from these findings · optional, downstream
          </span>
        </span>
        {data && data.artifacts.length > 0 && (
          <span className="text-[11px] font-mono text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5">
            {data.artifacts.length}
          </span>
        )}
        <Chevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="px-5 pb-5 pt-1 border-t border-zinc-800">
          {loading && (
            <p className="text-sm text-zinc-400 animate-pulse pt-3">Generating detection package…</p>
          )}
          {!loading && failed && (
            <p className="text-sm text-zinc-400 pt-3">
              The detection package could not be generated. The investigation above is unaffected.
            </p>
          )}
          {!loading && !failed && data && <PackageView data={data} />}
        </div>
      )}
    </section>
  );
}

function PackageView({ data }: { data: DetectionPackage }) {
  const empty = data.artifacts.length === 0;
  return (
    <div className="space-y-4 pt-3">
      {empty ? (
        <div
          className="flex items-start gap-3 rounded-xl border border-zinc-700/60 bg-zinc-800/40 p-4"
          role="status"
        >
          <InfoIcon />
          <div className="min-w-0 space-y-1">
            <p className="text-sm font-medium text-zinc-200">No detection artifacts generated.</p>
            <p className="text-sm text-zinc-400 leading-relaxed">
              The Detection Engineering framework is active and consuming this investigation, but no
              detection generators are enabled yet. Sigma, YARA, and SIEM/EDR generators arrive in a
              future phase — they will appear here automatically, with no change to the findings
              above.
            </p>
          </div>
        </div>
      ) : (
        <ul className="space-y-2">
          {data.artifacts.map((artifact) => (
            <ArtifactRow key={artifact.id} artifact={artifact} />
          ))}
        </ul>
      )}

      <p className="text-[11px] text-zinc-600 border-t border-zinc-800 pt-3">
        Detection Engine v{data.metadata.engine_version} · derived from Reasoning Engine v
        {data.metadata.source_engine_version} · {data.metadata.source_finding_count} finding(s).
        Detection content is downstream and advisory; the deterministic findings above are
        authoritative.
      </p>
    </div>
  );
}

/** A single artifact row — metadata only; rule content is not rendered yet. */
function ArtifactRow({ artifact }: { artifact: DetectionArtifact }) {
  return (
    <li className="flex items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-950/40 px-4 py-2.5">
      <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 bg-zinc-800 rounded px-1.5 py-0.5">
        {artifact.language}
      </span>
      <span className="flex-1 min-w-0 text-sm text-zinc-200 truncate">{artifact.title}</span>
      <span className="text-[10px] font-mono text-zinc-600">{artifact.id}</span>
    </li>
  );
}

function ShieldIcon() {
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
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
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
