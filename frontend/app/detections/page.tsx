"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getInvestigation, listInvestigations, testDetection, updateInvestigation, type DetectionArtifact, type DetectionReviewStatus, type WorkspaceInvestigation } from "@/lib/api";
import { detectionLanguageLabel, detectionSeverityClass, detectionSeverityLabel, artifactFilename } from "@/lib/detection";
import { readDetectionVersions, versionHistoryExportName, withDetectionVersion } from "@/lib/detectionVersioning";

type Rule = DetectionArtifact & { investigationId: string; investigationTitle: string };
type RuleGroup = { key: string; title: string; investigationId: string; investigationTitle: string; rules: Rule[] };

export default function DetectionsPage() {
  const [records, setRecords] = useState<WorkspaceInvestigation[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [language, setLanguage] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [iocType, setIocType] = useState("all");
  const [reviewStatus, setReviewStatus] = useState("all");
  const [expandAll, setExpandAll] = useState(false);
  const [expandSignal, setExpandSignal] = useState(0);
  const [query, setQuery] = useState("");
  const [showExcluded, setShowExcluded] = useState(false);
  const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(1);
  const pageSize = 10;

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
    .filter((rule) => severity === "all" || rule.severity === Number(severity))
    .filter((rule) => iocType === "all" || getIocType(rule.title) === iocType)
    .filter((rule) => reviewStatus === "all" || rule.review_status === reviewStatus)
    .filter((rule) => showExcluded || rule.metadata?.excluded !== "true")
    .filter((rule) => `${rule.title} ${rule.description} ${rule.content}`.toLowerCase().includes(query.toLowerCase().trim())), [records, language, severity, iocType, reviewStatus, showExcluded, query]);
  const groups = useMemo<RuleGroup[]>(() => {
    const grouped = new Map<string, RuleGroup>();
    for (const rule of rules) {
      const key = `${rule.investigationId}:${rule.title}`;
      const existing = grouped.get(key);
      if (existing) existing.rules.push(rule);
      else grouped.set(key, { key, title: rule.title, investigationId: rule.investigationId, investigationTitle: rule.investigationTitle, rules: [rule] });
    }
    return [...grouped.values()].sort((a, b) => a.title.localeCompare(b.title));
  }, [rules]);
  const languages = [...new Set(records.flatMap((r) => r.detection_package?.languages ?? []))];
  const pageCount = Math.max(1, Math.ceil(groups.length / pageSize));
  const visibleGroups = groups.slice((page - 1) * pageSize, page * pageSize);
  useEffect(() => setPage(1), [language, severity, iocType, reviewStatus, query]);

  function exportRules() {
    const payload = rules.map(({ investigationId, investigationTitle, ...rule }) => ({ investigationId, investigationTitle, ...rule }));
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "threatlens-detections.json"; link.click(); URL.revokeObjectURL(link.href);
  }
  function exportSelectedSigma() {
    const selected = groups.filter((group) => selectedGroups.has(group.key));
    const types = new Set(selected.map((group) => getIocType(group.title)));
    if (types.size !== 1) { window.alert("Select IOCs of the same type to create a combined Sigma rule."); return; }
    const type = [...types][0];
    const values = selected.map((group) => group.title.split(":").slice(1).join(":").trim()).filter(Boolean);
    if (values.length < 2) return;
    const field = type === "domain" ? "query" : type === "ip" ? "dst_ip" : type === "url" ? "c-uri|contains" : "Hashes|contains";
    const category = type === "domain" ? "dns" : type === "ip" ? "firewall" : type === "url" ? "proxy" : "process_creation";
    const content = [`title: ThreatLens selected IOC match`, `status: experimental`, `logsource:`, `  category: ${category}`, `detection:`, `  selection:`, `    ${field}: [${values.map((value) => JSON.stringify(value)).join(", ")}]`, `  condition: selection`, ``].join("\n");
    const blob = new Blob([content], { type: "text/yaml" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "threatlens-selected-iocs.yml"; link.click(); URL.revokeObjectURL(link.href);
  }
  async function saveSelectedSigma() {
    const selected = groups.filter((group) => selectedGroups.has(group.key));
    const types = new Set(selected.map((group) => getIocType(group.title)));
    if (selected.length < 2 || types.size !== 1) { window.alert("Select at least two IOCs of the same type."); return; }
    const type = [...types][0]; const values = selected.map((group) => group.title.split(":").slice(1).join(":").trim()).filter(Boolean);
    const field = type === "domain" ? "query" : type === "ip" ? "dst_ip" : type === "url" ? "c-uri|contains" : "Hashes|contains";
    const category = type === "domain" ? "dns" : type === "ip" ? "network" : type === "url" ? "http" : "file";
    const content = [`title: ThreatLens selected IOC match`, `status: experimental`, `logsource:`, `  category: ${type === "domain" ? "dns" : type === "ip" ? "firewall" : type === "url" ? "proxy" : "process_creation"}`, `detection:`, `  selection:`, `    ${field}: [${values.map((value) => JSON.stringify(value)).join(", ")}]`, `  condition: selection`, ``].join("\n");
    const record = await getInvestigation(selected[0].investigationId); if (!record.detection_package) return;
    const id = `det_combined_${hashText(`${type}|${values.join("|")}`)}`;
    const artifact = { id, language: "sigma", target: { language: "sigma", platform: "generic" }, title: `Combined ${type} IOC match (${values.length})`, description: `Analyst-composed Sigma rule for ${values.length} selected ${type} indicators.`, content, severity: Math.max(...selected.flatMap((group) => group.rules.map((rule) => rule.severity))), category, capabilities: ["ioc_match"], source_finding_ids: selected.flatMap((group) => group.rules.flatMap((rule) => rule.source_finding_ids)), references: [], validation: { status: "valid", validator: "threatlens-sigma-composer", messages: [] }, review_status: "draft", review_note: "Analyst-composed draft; verify against the target schema.", reviewed_at: null, reviewed_by: null, rule_id: id, metadata: { generator: "analyst-composer", combined: "true", version: "1", source_iocs: values.join(",") } } as unknown as DetectionArtifact;
    const previous = record.detection_package.artifacts.find((item) => item.id === id);
    const versioned = previous ? withDetectionVersion(previous, artifact) : artifact;
    const pkg = { ...record.detection_package, artifacts: [...record.detection_package.artifacts.filter((item) => item.id !== id), versioned] };
    const updated = await updateInvestigation(record.id, { detection_package: pkg });
    setRecords((items) => items.map((item) => item.id === updated.id ? updated : item)); setSelectedGroups(new Set()); window.alert("Combined Sigma rule saved as a draft for review.");
  }

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
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filter by severity" className="rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none"><option value="all">All severities</option>{[4, 3, 2, 1, 0].map((item) => <option key={item} value={item}>{detectionSeverityLabel(item)}</option>)}</select>
          <select value={iocType} onChange={(e) => setIocType(e.target.value)} aria-label="Filter by IOC type" className="rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none"><option value="all">All IOC types</option><option value="domain">Domains</option><option value="ip">IP addresses</option><option value="url">URLs</option><option value="hash">File hashes</option></select>
          <select value={reviewStatus} onChange={(e) => setReviewStatus(e.target.value)} aria-label="Filter by review status" className="rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 outline-none"><option value="all">All review statuses</option><option value="unreviewed">Unreviewed</option><option value="reviewed">Reviewed</option><option value="approved">Approved</option><option value="rejected">Rejected</option></select>
          <label className="flex items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-400"><input type="checkbox" checked={showExcluded} onChange={(e) => setShowExcluded(e.target.checked)} /> Show excluded</label>
        </div>
        {state === "loading" && <Panel>Loading generated detections…</Panel>}
        {state === "error" && <Panel>Could not load saved detections. Check that the Workspace API is available.</Panel>}
        {state === "ready" && rules.length === 0 && <Panel>No generated detections match this view. Generate detections from an investigation, then save it to the Workspace.</Panel>}
        {state === "ready" && groups.length > 0 && <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-zinc-500">{groups.length} IOC{groups.length === 1 ? "" : "s"} · {rules.length} generated rule{rules.length === 1 ? "" : "s"} · {rules.filter((rule) => rule.review_status === "approved").length} approved</p><div className="flex flex-wrap gap-2"><button type="button" onClick={exportRules} className="rounded-lg border border-sky-500/30 px-3 py-1.5 text-xs text-sky-300 hover:bg-sky-500/10">Export filtered JSON</button>{selectedGroups.size > 1 && <><button type="button" onClick={exportSelectedSigma} className="rounded-lg border border-indigo-500/30 px-3 py-1.5 text-xs text-indigo-300 hover:bg-indigo-500/10">Export selected Sigma</button><button type="button" onClick={saveSelectedSigma} className="rounded-lg border border-emerald-500/30 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/10">Save combined draft</button></>}<button type="button" onClick={() => { setExpandAll(true); setExpandSignal((value) => value + 1); }} className="rounded-lg border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:bg-zinc-900">Expand all</button><button type="button" onClick={() => { setExpandAll(false); setExpandSignal((value) => value + 1); }} className="rounded-lg border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:bg-zinc-900">Collapse all</button></div></div>}
        <div className="grid gap-3">
          {visibleGroups.map((group) => <IocGroup key={group.key} group={group} selected={selectedGroups.has(group.key)} onSelect={(checked) => setSelectedGroups((current) => { const next = new Set(current); checked ? next.add(group.key) : next.delete(group.key); return next; })} expandAll={expandAll} expandSignal={expandSignal} onUpdated={(record) => setRecords((items) => items.map((item) => item.id === record.id ? record : item))} />)}
        </div>
        {state === "ready" && pageCount > 1 && <div className="flex items-center justify-between border-t border-zinc-800 pt-4"><button type="button" disabled={page === 1} onClick={() => setPage((value) => value - 1)} className="rounded-lg border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 disabled:opacity-40">Previous</button><span className="text-xs text-zinc-500">Page {page} of {pageCount}</span><button type="button" disabled={page === pageCount} onClick={() => setPage((value) => value + 1)} className="rounded-lg border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 disabled:opacity-40">Next</button></div>}
      </div>
    </main>
  );
}

function Panel({ children }: { children: ReactNode }) {
  return <div className="rounded-2xl border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500">{children}</div>;
}

function getIocType(title: string): string {
  const value = title.toLowerCase();
  if (value.includes("domain")) return "domain";
  if (value.includes("ip address")) return "ip";
  if (value.includes("url")) return "url";
  if (value.includes("hash")) return "hash";
  return "other";
}

function hashText(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) hash = Math.imul(hash ^ value.charCodeAt(index), 16777619);
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function IocGroup({ group, selected, onSelect, expandAll, expandSignal, onUpdated }: { group: RuleGroup; selected: boolean; onSelect: (checked: boolean) => void; expandAll: boolean; expandSignal: number; onUpdated: (record: WorkspaceInvestigation) => void }) {
  const [open, setOpen] = useState(group.rules.length === 1);
  useEffect(() => { if (expandSignal > 0) setOpen(expandAll); }, [expandAll, expandSignal]);
  const languages = [...new Set(group.rules.map((rule) => detectionLanguageLabel(rule.language)))];
  const highest = group.rules.reduce((value, rule) => Math.max(value, Number(rule.severity)), 0);
  const severity = highest;
  return <details className="group rounded-2xl border border-zinc-800 bg-zinc-900" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 p-4">
      <input type="checkbox" checked={selected} onChange={(event) => onSelect(event.target.checked)} onClick={(event) => event.stopPropagation()} aria-label={`Select ${group.title} for combined Sigma export`} />
      <span className="flex-1 text-sm font-medium text-white">{group.title}</span>
      <span className="text-xs text-zinc-500">{group.rules.length} format{group.rules.length === 1 ? "" : "s"}</span>
      <span className="hidden text-xs text-zinc-600 sm:inline">{languages.join(" · ")}</span>
      <span className={`rounded border px-2 py-0.5 text-[10px] ${detectionSeverityClass(severity)}`}>{detectionSeverityLabel(severity)}</span>
      <span className="text-zinc-600 group-open:rotate-180">⌄</span>
    </summary>
    <div className="space-y-2 border-t border-zinc-800 p-3">
      <p className="px-1 text-xs text-zinc-500">From <Link className="text-zinc-300 hover:underline" href={`/workspace/${group.investigationId}`}>{group.investigationTitle}</Link></p>
      {group.rules.map((rule) => <RuleCard key={`${rule.investigationId}-${rule.id}`} rule={rule} onUpdated={onUpdated} />)}
    </div>
  </details>;
}

function RuleCard({ rule, onUpdated }: { rule: Rule; onUpdated: (record: WorkspaceInvestigation) => void }) {
  const [sample, setSample] = useState('{"event_type":"process_start","Image":"powershell.exe"}');
  const [testResult, setTestResult] = useState<string | null>(null);
  const [note, setNote] = useState(rule.review_note ?? "");
  const [noteSaved, setNoteSaved] = useState(false);
  const versions = readDetectionVersions(rule);
  function downloadVersion(version: number, content: string) {
    const blob = new Blob([content], { type: "text/plain" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = versionHistoryExportName(rule, version); link.click(); URL.revokeObjectURL(link.href);
  }
  async function review(status: DetectionReviewStatus) {
    const record = await getInvestigation(rule.investigationId);
    if (!record.detection_package) return;
    const pkg = { ...record.detection_package, artifacts: record.detection_package.artifacts.map((item) => item.id === rule.id ? withDetectionVersion(item, { ...item, review_status: status, reviewed_at: new Date().toISOString(), reviewed_by: "local-analyst" }) : item) };
    const updated = await updateInvestigation(record.id, { detection_package: pkg });
    onUpdated(updated);
  }
  async function saveNote() {
    const record = await getInvestigation(rule.investigationId);
    if (!record.detection_package) return;
    const pkg = { ...record.detection_package, artifacts: record.detection_package.artifacts.map((item) => item.id === rule.id ? withDetectionVersion(item, { ...item, review_note: note }) : item) };
    const updated = await updateInvestigation(record.id, { detection_package: pkg });
    onUpdated(updated); setNoteSaved(true); setTimeout(() => setNoteSaved(false), 1800);
  }
  async function toggleExclusion() {
    const record = await getInvestigation(rule.investigationId);
    if (!record.detection_package) return;
    const excluded = rule.metadata?.excluded === "true";
    const pkg = { ...record.detection_package, artifacts: record.detection_package.artifacts.map((item) => item.id === rule.id ? withDetectionVersion(item, { ...item, metadata: { ...item.metadata, ...(excluded ? { excluded: "false", exclusion_reason: "" } : { excluded: "true", exclusion_reason: "Analyst excluded from detection workspace" }) } }) : item) };
    onUpdated(await updateInvestigation(record.id, { detection_package: pkg }));
  }
  function download() {
    const blob = new Blob([rule.content], { type: "text/plain" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = artifactFilename(rule); link.click(); URL.revokeObjectURL(link.href);
  }
  async function runTest() {
    try {
      const logs = sample.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
      const result = await testDetection(rule.language, rule.content, logs);
      setTestResult(result.messages.join(" ") || `${result.matched_logs}/${result.total_logs} sample log(s) matched.`);
    } catch { setTestResult("Enter one valid JSON log per line."); }
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
      {versions.length > 0 && <details className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><summary className="cursor-pointer text-xs font-medium text-zinc-300">Version history ({versions.length})</summary><div className="mt-3 space-y-2">{versions.map((version) => <div key={version.version} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-zinc-800 p-2 text-xs"><span className="text-zinc-400">v{version.version} · {version.changed_fields.join(", ")} · {new Date(version.created_at).toLocaleString()}</span><button type="button" onClick={() => downloadVersion(version.version, version.content)} className="rounded border border-zinc-700 px-2 py-1 text-zinc-300 hover:bg-zinc-800">Export v{version.version}</button></div>)}</div></details>}
      <div className="flex flex-wrap gap-2"><button type="button" onClick={() => navigator.clipboard?.writeText(rule.content)} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">Copy rule</button><button type="button" onClick={download} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">Download</button><button type="button" onClick={toggleExclusion} className="rounded-lg border border-amber-500/30 px-3 py-1.5 text-xs text-amber-300 hover:bg-amber-500/10">{rule.metadata?.excluded === "true" ? "Restore" : "Exclude"}</button><button type="button" onClick={() => review("reviewed")} className="rounded-lg border border-sky-500/30 px-3 py-1.5 text-xs text-sky-300 hover:bg-sky-500/10">Mark reviewed</button><button type="button" onClick={() => review("approved")} className="rounded-lg border border-emerald-500/30 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/10">Approve</button><button type="button" onClick={() => review("rejected")} className="rounded-lg border border-red-500/30 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/10">Reject</button></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><label htmlFor={`note-${rule.id}`} className="text-xs font-medium text-zinc-300">Analyst note</label><textarea id={`note-${rule.id}`} value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Record tuning decisions, exceptions, or review context…" className="mt-2 w-full rounded-lg border border-zinc-800 bg-zinc-900 p-2 text-xs text-zinc-300 placeholder-zinc-600" /><button type="button" onClick={saveNote} className="mt-2 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">{noteSaved ? "Saved" : "Save note"}</button></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><p className="text-xs font-medium text-zinc-300">Offline sample test</p><p className="mt-1 text-[11px] text-zinc-600">One JSON log per line. This never contacts a SIEM.</p><textarea value={sample} onChange={(e) => setSample(e.target.value)} rows={3} className="mt-2 w-full rounded-lg border border-zinc-800 bg-zinc-900 p-2 font-mono text-xs text-zinc-300" /><button onClick={runTest} className="mt-2 rounded-lg border border-indigo-500/30 px-3 py-1.5 text-xs text-indigo-300 hover:bg-indigo-500/10">Test samples</button>{testResult && <p className="mt-2 text-xs text-zinc-400">{testResult}</p>}</div>
    </div>
  </details>;
}
