"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  generateDetections,
  type DetectionArtifact,
  type DetectionMetadata,
  type DetectionPackage,
  type Finding,
  type InvestigationSummary,
} from "@/lib/api";
import {
  artifactFilename,
  detectionSeverityClass,
  detectionSeverityLabel,
  groupByLanguage,
  mitreFromMetadata,
  mitreTechniqueUrl,
  type LanguageGroup,
} from "@/lib/detection";
import { confidenceBandLabel, findingsByIds } from "@/lib/investigation";
import {
  Badge,
  Chevron,
  CodeViewer,
  DetailTabs,
  Field,
  IconButton,
  InfoIcon,
  LanguageGroupHeader,
  type DetailTab,
} from "./shared/DetectionDisclosure";
import { FindingCard } from "./FindingsSection";

interface Props {
  summary: InvestigationSummary;
}

/**
 * The Detection Engineering panel — a downstream, optional consumer of the
 * deterministic summary. Collapsed by default; the DetectionPackage is fetched
 * lazily on first expand. Analysts drill down Language → Rule → Rule Details
 * rather than scanning one long list of full rule bodies.
 */
export function DetectionEngineeringCard({ summary }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<DetectionPackage | null>(null);
  const [failed, setFailed] = useState(false);
  const [openLanguages, setOpenLanguages] = useState<ReadonlySet<string>>(new Set());
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const abortRef = useRef<AbortController | null>(null);

  // Reset when a new investigation arrives (the summary identity changes).
  useEffect(() => {
    abortRef.current?.abort();
    setExpanded(false);
    setData(null);
    setFailed(false);
    setLoading(false);
    setOpenLanguages(new Set());
    setSelectedId(null);
    setActiveTab("overview");
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

  function toggleLanguage(language: string) {
    setOpenLanguages((prev) => {
      const next = new Set(prev);
      if (next.has(language)) next.delete(language);
      else next.add(language);
      return next;
    });
  }

  // Selecting a different rule always returns to the Overview tab; re-selecting
  // the open rule collapses its detail panel.
  function selectArtifact(id: string) {
    setSelectedId((prev) => {
      if (prev === id) return null;
      setActiveTab("overview");
      return id;
    });
  }

  const groups = useMemo(() => (data ? groupByLanguage(data.artifacts) : []), [data]);

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
          {!loading && !failed && data && (
            <PackageView
              data={data}
              groups={groups}
              findings={summary.findings}
              openLanguages={openLanguages}
              onToggleLanguage={toggleLanguage}
              selectedId={selectedId}
              onSelectArtifact={selectArtifact}
              activeTab={activeTab}
              onTabChange={setActiveTab}
            />
          )}
        </div>
      )}
    </section>
  );
}

interface PackageViewProps {
  data: DetectionPackage;
  groups: LanguageGroup<DetectionArtifact>[];
  findings: Finding[];
  openLanguages: ReadonlySet<string>;
  onToggleLanguage: (language: string) => void;
  selectedId: string | null;
  onSelectArtifact: (id: string) => void;
  activeTab: string;
  onTabChange: (key: string) => void;
}

function PackageView({
  data,
  groups,
  findings,
  openLanguages,
  onToggleLanguage,
  selectedId,
  onSelectArtifact,
  activeTab,
  onTabChange,
}: PackageViewProps) {
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
        {groups.length} language{groups.length === 1 ? "" : "s"} · {data.artifacts.length} rule
        {data.artifacts.length === 1 ? "" : "s"}
      </p>
      <div className="space-y-2">
        {groups.map((group) => (
          <LanguageGroupHeader
            key={group.language}
            id={`det-lang-${group.language}`}
            label={group.label}
            count={group.items.length}
            expanded={openLanguages.has(group.language)}
            onToggle={() => onToggleLanguage(group.language)}
          >
            <ul className="space-y-2">
              {group.items.map((artifact) => (
                <li key={artifact.id}>
                  <ArtifactRow
                    artifact={artifact}
                    packageMeta={data.metadata}
                    findings={findings}
                    selected={selectedId === artifact.id}
                    onSelect={() => onSelectArtifact(artifact.id)}
                    activeTab={activeTab}
                    onTabChange={onTabChange}
                  />
                </li>
              ))}
            </ul>
          </LanguageGroupHeader>
        ))}
      </div>
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

interface ArtifactRowProps {
  artifact: DetectionArtifact;
  packageMeta: DetectionMetadata;
  findings: Finding[];
  selected: boolean;
  onSelect: () => void;
  activeTab: string;
  onTabChange: (key: string) => void;
}

/** A rule's scan-first row: title, severity, finding count, platform, timestamp — no body. */
function ArtifactRow({
  artifact,
  packageMeta,
  findings,
  selected,
  onSelect,
  activeTab,
  onTabChange,
}: ArtifactRowProps) {
  const linked = useMemo(
    () => findingsByIds(findings, artifact.source_finding_ids),
    [findings, artifact.source_finding_ids],
  );

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 overflow-hidden">
      <button
        onClick={onSelect}
        aria-expanded={selected}
        className="w-full flex flex-wrap items-center gap-2 px-3 py-2.5 text-left hover:bg-zinc-800/40 transition-colors"
      >
        <span className="flex-1 min-w-0 text-sm text-zinc-200 truncate">{artifact.title}</span>
        <Badge className={detectionSeverityClass(artifact.severity)}>
          {detectionSeverityLabel(artifact.severity)}
        </Badge>
        <span className="text-[10px] text-zinc-500 font-mono">
          {artifact.source_finding_ids.length} finding{artifact.source_finding_ids.length === 1 ? "" : "s"}
        </span>
        <Badge className="text-zinc-400 bg-zinc-800/60 border-zinc-700">{artifact.target.platform}</Badge>
        <span className="hidden sm:inline text-[10px] text-zinc-600">{packageMeta.generated_at}</span>
        <Chevron expanded={selected} />
      </button>

      {selected && (
        <div className="border-t border-zinc-800 p-3">
          <DetailTabs
            idPrefix={artifact.id}
            activeKey={activeTab}
            onChange={onTabChange}
            tabs={buildArtifactTabs(artifact, linked, packageMeta)}
          />
        </div>
      )}
    </div>
  );
}

function buildArtifactTabs(
  artifact: DetectionArtifact,
  linked: Finding[],
  packageMeta: DetectionMetadata,
): DetailTab[] {
  return [
    { key: "overview", label: "Overview", content: <OverviewTab artifact={artifact} linked={linked} packageMeta={packageMeta} /> },
    { key: "rule", label: "Rule", content: <CodeViewer content={artifact.content} /> },
    { key: "findings", label: "Findings", content: <FindingsTab linked={linked} /> },
    { key: "mitre", label: "MITRE", content: <MitreTab artifact={artifact} linked={linked} /> },
    { key: "metadata", label: "Metadata", content: <MetadataTab artifact={artifact} /> },
  ];
}

function OverviewTab({
  artifact,
  linked,
  packageMeta,
}: {
  artifact: DetectionArtifact;
  linked: Finding[];
  packageMeta: DetectionMetadata;
}) {
  const [copied, setCopied] = useState(false);
  const confidence = linked.reduce<Finding["confidence"] | null>(
    (best, f) => (!best || f.confidence.score > best.score ? f.confidence : best),
    null,
  );

  async function copy() {
    try {
      await navigator.clipboard.writeText(artifact.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — the rule text is still visible in the Rule tab */
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
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px] sm:grid-cols-3">
        <Field label="Rule Name" value={artifact.title} />
        <Field label="Detection ID" value={artifact.id} mono />
        <Field label="Rule ID" value={artifact.rule_id ?? "—"} mono />
        <Field label="Severity" value={detectionSeverityLabel(artifact.severity)} />
        <Field label="Confidence" value={confidence ? confidenceBandLabel(confidence.band) : "—"} />
        <Field label="Finding IDs" value={artifact.source_finding_ids.join(", ") || "—"} mono />
        <Field label="Platform" value={artifact.target.platform} />
        <Field label="Language" value={artifact.language} mono />
        <Field label="Generated" value={packageMeta.generated_at} />
        <Field label="Engine Version" value={packageMeta.engine_version} />
      </div>
      <div className="flex gap-1.5 pt-1">
        <IconButton label={copied ? "Copied" : "Copy"} onClick={copy} />
        <IconButton label="Download" onClick={download} />
      </div>
    </div>
  );
}

function FindingsTab({ linked }: { linked: Finding[] }) {
  if (linked.length === 0) {
    return <p className="text-xs text-zinc-500">No linked findings.</p>;
  }
  return (
    <div className="space-y-2">
      {linked.map((finding) => (
        <FindingCard key={finding.id} finding={finding} />
      ))}
    </div>
  );
}

function MitreTab({ artifact, linked }: { artifact: DetectionArtifact; linked: Finding[] }) {
  const fromMetadata = mitreFromMetadata(artifact.metadata);
  const fromFindings = linked.flatMap((f) =>
    f.relationships
      .filter((r) => r.relationship.target_type === "attack_pattern")
      .map((r) => r.relationship.target_value),
  );
  const techniques = Array.from(new Set([...fromMetadata, ...fromFindings]));

  if (techniques.length === 0) {
    return <p className="text-xs text-zinc-500">No ATT&amp;CK mappings for this rule.</p>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {techniques.map((technique) => (
        <a key={technique} href={mitreTechniqueUrl(technique)} target="_blank" rel="noreferrer noopener">
          <Badge className="text-indigo-300 bg-indigo-500/10 border-indigo-500/30 hover:bg-indigo-500/20">
            {technique}
          </Badge>
        </a>
      ))}
    </div>
  );
}

function MetadataTab({ artifact }: { artifact: DetectionArtifact }) {
  const entries = Object.entries(artifact.metadata);
  return (
    <div className="space-y-3">
      {entries.length > 0 && (
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px] sm:grid-cols-3">
          {entries.map(([key, value]) => (
            <Field key={key} label={key} value={value} mono />
          ))}
        </div>
      )}
      <div>
        <p className="text-[9px] uppercase tracking-wider text-zinc-600 mb-1">Validation</p>
        <Badge className="text-zinc-400 bg-zinc-800/60 border-zinc-700">
          {artifact.validation.status}
        </Badge>
      </div>
      {artifact.references.length > 0 && (
        <div>
          <p className="text-[9px] uppercase tracking-wider text-zinc-600 mb-1">References</p>
          <ul className="space-y-1 text-[11px]">
            {artifact.references.map((reference, i) => (
              <li key={i}>
                {reference.url ? (
                  <a
                    href={reference.url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-sky-400 hover:text-sky-300"
                  >
                    {reference.title}
                  </a>
                ) : (
                  <span className="text-zinc-400">{reference.title}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
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
