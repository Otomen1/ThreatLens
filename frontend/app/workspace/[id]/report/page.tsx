"use client";

// The analyst report view (Phase 8.4): a deterministic projection of one
// saved investigation's existing outputs, fetched in a single call and
// rendered for readability and browser print/Save-as-PDF — visually
// distinct from the interactive workspace page, with no editing and no
// AI-generated content.

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import { getInvestigationReport, type InvestigationReport } from "@/lib/api";
import { ReportActions } from "@/components/workspace/report/ReportActions";
import { ReportAssessment } from "@/components/workspace/report/ReportAssessment";
import { ReportCorrelation } from "@/components/workspace/report/ReportCorrelation";
import { ReportDetections } from "@/components/workspace/report/ReportDetections";
import { ReportFindings } from "@/components/workspace/report/ReportFindings";
import { ReportGraphSummary } from "@/components/workspace/report/ReportGraphSummary";
import { ReportHeader } from "@/components/workspace/report/ReportHeader";
import { ReportRecommendations } from "@/components/workspace/report/ReportRecommendations";
import { ReportThreatIntelligence } from "@/components/workspace/report/ReportThreatIntelligence";
import { ReportTimeline } from "@/components/workspace/report/ReportTimeline";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; report: InvestigationReport };

export default function InvestigationReportPage() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<State>({ kind: "loading" });
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ kind: "loading" });
    try {
      const report = await getInvestigationReport(params.id, controller.signal);
      setState({ kind: "ready", report });
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

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14 print:p-0 bg-zinc-950 print:bg-white">
      <div className="w-full max-w-3xl mx-auto space-y-6 print:space-y-4">
        <Link
          href={
            state.kind === "ready" ? `/workspace/${state.report.investigation.id}` : "/workspace"
          }
          className="print:hidden text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          ← Back to Investigation
        </Link>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Loading report…
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
            <ReportActions report={state.report} />
            <ReportHeader report={state.report} />

            {state.report.investigation.investigation_summary && (
              <>
                <ReportAssessment summary={state.report.investigation.investigation_summary} />
                <ReportFindings
                  findings={state.report.investigation.investigation_summary.findings}
                />
                <ReportRecommendations
                  recommendations={
                    state.report.investigation.investigation_summary.recommendations
                  }
                />
                <ReportThreatIntelligence
                  findings={state.report.investigation.investigation_summary.findings}
                />
              </>
            )}

            <ReportCorrelation correlation={state.report.investigation.correlation_summary} />
            <ReportTimeline timeline={state.report.timeline} />
            <ReportGraphSummary graph={state.report.graph} />

            {state.report.investigation.detection_package && (
              <ReportDetections pkg={state.report.investigation.detection_package} />
            )}

            {!state.report.investigation.investigation_summary &&
              !state.report.investigation.detection_package &&
              !state.report.investigation.correlation_summary && (
                <div className="bg-zinc-900 print:bg-white border border-zinc-800 print:border-zinc-300 rounded-2xl p-8 text-center text-sm text-zinc-500 print:text-zinc-700">
                  This saved investigation has no attached results yet.
                </div>
              )}
          </>
        )}
      </div>
    </main>
  );
}
