"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getInvestigation, listInvestigations, updateInvestigation, type DetectionArtifact, type DetectionReviewStatus, type WorkspaceInvestigation } from "@/lib/api";
import { detectionLanguageLabel, detectionSeverityClass, detectionSeverityLabel, artifactFilename } from "@/lib/detection";

type Rule = DetectionArtifact & { investigationId: string; investigationTitle: string };

export default function DetectionsPage() {
  const [records, setRecords] = useState<WorkspaceInvestigation[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [language, setLanguage] = useState("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    (async () => {
      try {
        const listed = await listInvestigations({}, controller.signal);
        const loaded = await Promise.all(listed.investigations.map((item) => getInvestigation(item.id, controller.signal)));
        setRecords(loaded);
        setState("ready");
      } catch (error) {
        if (!(error instanceof DOMException && error.name === "AbortError")) setState("error");
      }
    })();
    return () => controller.abort();
  }, []);

  const rules = useMemo(() => records.flatMap((record) =>
    (record.detection_package?.artifacts ?? []).map((artifact) => ({
      ...artifact, investigationId: record.id, investigationTitle: record.title,
    })),
  ).filter((rule) => language === "all" || rule.language === language)
    .filter((rule) => `${rule.title} ${rule.description} ${rule.content}`.toLowerCase().includes(query.toLowerCase().trim())), [records, language, query]);
  const languages = [...new Set(records.flatMap((r) => r.detection_package?.languages ?? []))];

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="mx-auto w-full max-w-6xl space-y-6">
        <header>
          <Link href="/workspace" className="text-xs text-zinc-500 hover:text-zinc-300">← Investigation Workspace</Link>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">Detection Workspace</h1>
          <p className="mt-1 text-sm text-zinc-500">Generated rules from saved investigations, organized for review and export.</p>
        </header>
        <div className="flex flex-wrap gap-2">
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search rules…" aria-label="Search detection rules" className="min-w-[220px] flex-1 rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm outline-none focus:border-zinc-600" />
          <select value={language} onChange={(e) => setLanguage(e.target.value)} aria-label="Filter by detection language" className="rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none">
            <option value="all">All languages</option>{languages.map((item) => <option key={item} value={item}>{detectionLanguageLabel(item)}</option>)}
          </select>
        </div>
        {state === "loading" && <Panel>Loading generated detections…</Panel>}
        {state === "error" && <Panel>Could not load saved detections. Check that the Workspace API is available.</Panel>}
        {state === "ready" && rules.length === 0 && <Panel>No generated detections match this view. Generate detections from an investigation, then save it to the Workspace.</Panel>}
        <div className="grid gap-3">
          {rules.map((rule) => <RuleCard key={`${rule.investigationId}-${rule.id}`} rule={rule} onUpdated={(record) => setRecords((items) => items.map((item) => item.id === record.id ? record : item))} />)}
        </div>
      </div>
    </main>
  );
}

function Panel({ children }: { children: ReactNode }) {
  return <div className="rounded-2xl border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500">{children}</div>;
}

function RuleCard({ rule, onUpdated }: { rule: Rule; onUpdated: (record: WorkspaceInvestigation) => void }) {
  async function review(status: DetectionReviewStatus) {
    const record = await getInvestigation(rule.investigationId);
    if (!record.detection_package) return;
    const pkg = { ...record.detection_package, artifacts: record.detection_package.artifacts.map((item) => item.id === rule.id ? { ...item, review_status: status, reviewed_at: new Date().toISOString(), reviewed_by: "local-analyst" } : item) };
    const updated = await updateInvestigation(record.id, { detection_package: pkg });
    onUpdated(updated);
  }
  function download() {
    const blob = new Blob([rule.content], { type: "text/plain" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = artifactFilename(rule); link.click(); URL.revokeObjectURL(link.href);
  }
  return <details className="group rounded-2xl border border-zinc-800 bg-zinc-900">
    <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 p-4">
      <span className="flex-1 text-sm font-medium text-white">{rule.title}</span>
      <span className="rounded border border-zinc-700 px-2 py-0.5 font-mono text-[10px] text-zinc-400">{detectionLanguageLabel(rule.language)}</span>
      <span className={`rounded border px-2 py-0.5 text-[10px] ${detectionSeverityClass(rule.severity)}`}>{detectionSeverityLabel(rule.severity)}</span>
      <span className="text-zinc-600 group-open:rotate-180">⌄</span>
    </summary>
    <div className="border-t border-zinc-800 p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500"><span>From <Link className="text-zinc-300 hover:underline" href={`/workspace/${rule.investigationId}`}>{rule.investigationTitle}</Link></span><span>{rule.validation.status} · {rule.review_status}</span></div>
      {rule.description && <p className="text-sm text-zinc-400">{rule.description}</p>}
      <pre className="max-h-[420px] overflow-auto rounded-xl border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs leading-5 text-zinc-300">{rule.content || "No rule content was generated."}</pre>
      <div className="flex flex-wrap gap-2"><button onClick={() => navigator.clipboard?.writeText(rule.content)} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">Copy rule</button><button onClick={download} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">Download</button><button onClick={() => review("reviewed")} className="rounded-lg border border-sky-500/30 px-3 py-1.5 text-xs text-sky-300 hover:bg-sky-500/10">Mark reviewed</button><button onClick={() => review("approved")} className="rounded-lg border border-emerald-500/30 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/10">Approve</button><button onClick={() => review("rejected")} className="rounded-lg border border-red-500/30 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/10">Reject</button></div>
    </div>
  </details>;
}
