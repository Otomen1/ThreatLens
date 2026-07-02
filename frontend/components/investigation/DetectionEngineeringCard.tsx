"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";

import {
  generateDetections,
  type DetectionArtifact,
  type DetectionPackage,
  type InvestigationSummary,
} from "@/lib/api";
import { artifactFilename, detectionSeverityClass, detectionSeverityLabel } from "@/lib/detection";

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
  if (data.artifacts.length === 0) {
    return (
      <div className="space-y-4 pt-3">
        <div
          className="flex items-start gap-3 rounded-xl border border-zinc-700/60 bg-zinc-800/40 p-4"
          role="status"
        >
          <InfoIcon />
          <div className="min-w-0 space-y-1">
            <p className="text-sm font-medium text-zinc-200">No detection artifacts generated.</p>
            <p className="text-sm text-zinc-400 leading-relaxed">
              No detections could be derived from these findings. Detection content is generated for
              log-observable indicators (IPs, domains, URLs, file hashes); knowledge findings such as
              techniques or actors do not produce standalone rules.
            </p>
          </div>
        </div>
        <PackageFooter data={data} />
      </div>
    );
  }

  return (
    <div className="space-y-3 pt-3">
      <p className="text-[11px] text-zinc-500 uppercase tracking-wider">
        Detection Artifacts ({data.artifacts.length})
      </p>
      <ul className="space-y-3">
        {data.artifacts.map((artifact) => (
          <li key={artifact.id}>
            <ArtifactCard artifact={artifact} />
          </li>
        ))}
      </ul>
      <PackageFooter data={data} />
    </div>
  );
}

function PackageFooter({ data }: { data: DetectionPackage }) {
  return (
    <p className="text-[11px] text-zinc-600 border-t border-zinc-800 pt-3">
      Detection Engine v{data.metadata.engine_version} · derived from Reasoning Engine v
      {data.metadata.source_engine_version} · {data.metadata.source_finding_count} finding(s).
      Detection content is downstream and advisory; the deterministic findings above are
      authoritative.
    </p>
  );
}

/** A single read-only detection artifact: metadata badges + the rule text. */
function ArtifactCard({ artifact }: { artifact: DetectionArtifact }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(artifact.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — no-op, the rule text is visible below */
    }
  }

  function download() {
    const blob = new Blob([artifact.content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = artifactFilename(artifact);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-zinc-800">
        <Badge className="uppercase tracking-wider text-zinc-300 bg-zinc-800 border-zinc-700">
          {artifact.language}
        </Badge>
        <span className="flex-1 min-w-0 text-sm font-medium text-zinc-200 truncate">
          {artifact.title}
        </span>
        <Badge className={detectionSeverityClass(artifact.severity)}>
          {detectionSeverityLabel(artifact.severity)}
        </Badge>
        <Badge className="text-zinc-400 bg-zinc-800/60 border-zinc-700">{artifact.category}</Badge>
      </div>

      {artifact.source_finding_ids.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 px-4 pt-3">
          <span className="text-[10px] uppercase tracking-wider text-zinc-600">Findings</span>
          {artifact.source_finding_ids.map((id) => (
            <span key={id} className="text-[10px] font-mono text-zinc-500">
              {id}
            </span>
          ))}
        </div>
      )}

      <div className="relative px-4 py-3">
        <div className="absolute right-5 top-5 flex gap-1.5">
          <IconButton label={copied ? "Copied" : "Copy"} onClick={copy} />
          <IconButton label="Download" onClick={download} />
        </div>
        <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 text-[11px] leading-relaxed text-zinc-300">
          <code className="font-mono whitespace-pre">{artifact.content}</code>
        </pre>
      </div>
    </div>
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
