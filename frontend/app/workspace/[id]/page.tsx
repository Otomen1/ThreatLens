"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  getInvestigation,
  getInvestigationTimeline,
  updateInvestigation,
  type Timeline,
  type WorkspaceInvestigation,
  type WorkspaceStatus,
} from "@/lib/api";
import { entityLabel, severityClasses, severityLabel } from "@/lib/investigation";
import { FindingsSection } from "@/components/investigation/FindingsSection";
import { InvestigationSummaryCard } from "@/components/investigation/InvestigationSummaryCard";
import { RecommendationRollup } from "@/components/investigation/RecommendationRollup";
import { Chevron } from "@/components/investigation/shared/DetectionDisclosure";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; record: WorkspaceInvestigation };

const STATUS_OPTIONS: WorkspaceStatus[] = ["open", "in_progress", "closed", "archived"];

export default function WorkspaceDetailPage() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<State>({ kind: "loading" });
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ kind: "loading" });
    try {
      const record = await getInvestigation(params.id, controller.signal);
      setState({ kind: "ready", record });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not reach the service.",
      });
    }
  }, [params.id]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  async function changeStatus(status: WorkspaceStatus) {
    if (state.kind !== "ready") return;
    try {
      const record = await updateInvestigation(state.record.id, { status });
      setState({ kind: "ready", record });
    } catch {
      // The select simply reflects the unchanged record on the next render.
    }
  }

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-4xl mx-auto space-y-4">
        <Link
          href="/workspace"
          className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          ← Back to Workspace
        </Link>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Loading investigation…
          </div>
        )}

        {state.kind === "error" && (
          <div
            role="alert"
            className="bg-red-500/10 border border-red-500/30 text-red-300 text-sm rounded-xl px-4 py-3"
          >
            {state.message}
          </div>
        )}

        {state.kind === "ready" && (
          <>
            <DetailHeader record={state.record} onStatusChange={changeStatus} />

            {state.record.investigation_summary && (
              <>
                <InvestigationSummaryCard summary={state.record.investigation_summary} />
                <RecommendationRollup
                  recommendations={state.record.investigation_summary.recommendations}
                />
                <FindingsSection findings={state.record.investigation_summary.findings} />
              </>
            )}

            <TimelineSection investigationId={state.record.id} />

            {state.record.detection_package && (
              <DetectionPackageSummary pkg={state.record.detection_package} />
            )}

            {state.record.correlation_summary && (
              <CorrelationSummaryPanel data={state.record.correlation_summary} />
            )}

            {!state.record.investigation_summary &&
              !state.record.detection_package &&
              !state.record.correlation_summary && (
                <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
                  This saved investigation has no attached results yet.
                </div>
              )}
          </>
        )}
      </div>
    </main>
  );
}

function DetailHeader({
  record,
  onStatusChange,
}: {
  record: WorkspaceInvestigation;
  onStatusChange: (status: WorkspaceStatus) => void;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-xs text-zinc-500 mb-1">{entityLabel(record.investigation_type)}</p>
          <h1 className="text-xl font-semibold text-white break-words">{record.title}</h1>
        </div>
        <select
          value={record.status}
          onChange={(e) => onStatusChange(e.target.value as WorkspaceStatus)}
          aria-label="Investigation status"
          className="shrink-0 bg-zinc-800 border border-zinc-700 rounded-lg px-2.5 py-1.5 text-xs text-zinc-300 focus:outline-none"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s.replace("_", " ")}
            </option>
          ))}
        </select>
      </div>

      {record.summary && <p className="text-sm text-zinc-400">{record.summary}</p>}

      <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-zinc-800">
        {record.severity !== null && (
          <span
            className={`text-[10px] px-2 py-0.5 rounded-full border ${severityClasses(record.severity)}`}
          >
            {severityLabel(record.severity)}
          </span>
        )}
        {record.tags.map((tag) => (
          <span
            key={tag}
            className="text-[10px] text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5"
          >
            {tag}
          </span>
        ))}
        <span className="text-[11px] text-zinc-600 ml-auto">
          Created {new Date(record.created_at).toLocaleString()}
        </span>
      </div>
    </div>
  );
}

/**
 * A collapsed-by-default, read-only timeline of chronological events derived
 * from the investigation's already-timestamped evidence — fetched lazily on
 * first expand, mirroring the existing Detection Engineering card's pattern.
 * Never re-sorts or re-derives what the backend returns.
 */
function TimelineSection({ investigationId }: { investigationId: string }) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [timeline, setTimeline] = useState<Timeline | null>(null);
  const [failed, setFailed] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (!next || timeline !== null || loading) return;

    setLoading(true);
    setFailed(false);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      setTimeline(await getInvestigationTimeline(investigationId, controller.signal));
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
      aria-label="Timeline"
    >
      <button
        onClick={toggle}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-zinc-800/40 transition-colors"
        aria-expanded={expanded}
      >
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-semibold text-white">Timeline</span>
          <span className="block text-[11px] text-zinc-500">
            Chronological events derived from timestamped evidence · read-only
          </span>
        </span>
        {timeline && timeline.events.length > 0 && (
          <span className="text-[11px] font-mono text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5">
            {timeline.events.length}
          </span>
        )}
        <Chevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="px-5 pb-5 pt-1 border-t border-zinc-800">
          {loading && (
            <p className="text-sm text-zinc-400 animate-pulse pt-3">Deriving timeline…</p>
          )}
          {!loading && failed && (
            <p className="text-sm text-zinc-400 pt-3">
              The timeline could not be loaded. The investigation above is unaffected.
            </p>
          )}
          {!loading && !failed && timeline && timeline.events.length === 0 && (
            <p className="text-sm text-zinc-500 pt-3">
              No timestamped evidence was found for this investigation — no events to derive a
              timeline from.
            </p>
          )}
          {!loading && !failed && timeline && timeline.events.length > 0 && (
            <ul className="space-y-2 pt-3">
              {timeline.events.map((event) => (
                <li
                  key={event.event_id}
                  className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[11px] text-zinc-500 font-mono shrink-0">
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                    <span className="text-sm text-zinc-200 flex-1 min-w-0 truncate">
                      {event.title}
                    </span>
                    <span className="text-[10px] text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5">
                      {event.event_type.replace(/_/g, " ")}
                    </span>
                    {event.severity !== null && (
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded-full border ${severityClasses(event.severity)}`}
                      >
                        {severityLabel(event.severity)}
                      </span>
                    )}
                  </div>
                  {event.description && (
                    <p className="text-xs text-zinc-500 mt-1">{event.description}</p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}

function DetectionPackageSummary({
  pkg,
}: {
  pkg: NonNullable<WorkspaceInvestigation["detection_package"]>;
}) {
  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
      aria-label="Detection engineering"
    >
      <h2 className="text-sm font-semibold text-white mb-2">
        Detection Engineering
        <span className="ml-2 text-xs font-normal text-zinc-500">({pkg.artifacts.length})</span>
      </h2>
      {pkg.artifacts.length === 0 ? (
        <p className="text-sm text-zinc-500">
          No detection artifacts were generated for this investigation.
        </p>
      ) : (
        <ul className="space-y-1.5">
          {pkg.artifacts.map((artifact) => (
            <li key={artifact.id} className="flex items-center gap-2 text-sm text-zinc-300">
              <span className="truncate">{artifact.title}</span>
              <span className="text-[10px] text-zinc-500 bg-zinc-800 rounded-full px-2 py-0.5">
                {artifact.language}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function CorrelationSummaryPanel({ data }: { data: Record<string, unknown> }) {
  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
      aria-label="Correlation"
    >
      <h2 className="text-sm font-semibold text-white mb-2">Correlation</h2>
      <pre className="text-xs text-zinc-400 overflow-x-auto whitespace-pre-wrap break-words">
        {JSON.stringify(data, null, 2)}
      </pre>
    </section>
  );
}
