"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  recommendCommunityDetections,
  type CommunityRecommendation,
  type CommunityRule,
  type InvestigationSummary,
  type RuleMatch,
} from "@/lib/api";
import { detectionSeverityLabel, mitreTechniqueUrl, type LanguageGroup } from "@/lib/detection";
import {
  communityRuleFilename,
  groupMatchesByLanguage,
  isRedistributable,
  licenseSupportLabel,
  matchTypeClass,
  matchTypeLabel,
  similarityClass,
} from "@/lib/knowledge";
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

interface Props {
  summary: InvestigationSummary;
}

/**
 * The Detection Knowledge panel — a downstream, read-only consumer that
 * recommends *community* detections resembling the investigation. It follows
 * the same Language → Rule → Rule Details drill-down as Detection Engineering,
 * but the content is always kept visually and structurally separate: these
 * rules are authored elsewhere, carry their own provenance, and are never
 * merged with generated content.
 */
export function DetectionKnowledgeCard({ summary }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CommunityRecommendation | null>(null);
  const [failed, setFailed] = useState(false);
  const [openLanguages, setOpenLanguages] = useState<ReadonlySet<string>>(new Set());
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const abortRef = useRef<AbortController | null>(null);

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

  function toggleLanguage(language: string) {
    setOpenLanguages((prev) => {
      const next = new Set(prev);
      if (next.has(language)) next.delete(language);
      else next.add(language);
      return next;
    });
  }

  function selectRule(id: string) {
    setSelectedId((prev) => {
      if (prev === id) return null;
      setActiveTab("overview");
      return id;
    });
  }

  const groups = useMemo(() => (data ? groupMatchesByLanguage(data.matches) : []), [data]);
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
          {!loading && !failed && data && (
            <RecommendationView
              data={data}
              groups={groups}
              openLanguages={openLanguages}
              onToggleLanguage={toggleLanguage}
              selectedId={selectedId}
              onSelectRule={selectRule}
              activeTab={activeTab}
              onTabChange={setActiveTab}
            />
          )}
        </div>
      )}
    </section>
  );
}

interface RecommendationViewProps {
  data: CommunityRecommendation;
  groups: LanguageGroup<RuleMatch>[];
  openLanguages: ReadonlySet<string>;
  onToggleLanguage: (language: string) => void;
  selectedId: string | null;
  onSelectRule: (id: string) => void;
  activeTab: string;
  onTabChange: (key: string) => void;
}

function RecommendationView({
  data,
  groups,
  openLanguages,
  onToggleLanguage,
  selectedId,
  onSelectRule,
  activeTab,
  onTabChange,
}: RecommendationViewProps) {
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
          {groups.length} language{groups.length === 1 ? "" : "s"} · {data.matches.length} match
          {data.matches.length === 1 ? "" : "es"}
        </p>
        <Tally label="Exact" value={data.exact_count} />
        <Tally label="Partial" value={data.partial_count} />
        <Tally label="Related" value={data.related_count} />
      </div>
      <div className="space-y-2">
        {groups.map((group) => (
          <LanguageGroupHeader
            key={group.language}
            id={`com-lang-${group.language}`}
            label={group.label}
            count={group.items.length}
            expanded={openLanguages.has(group.language)}
            onToggle={() => onToggleLanguage(group.language)}
          >
            <ul className="space-y-2">
              {group.items.map((match) => (
                <li key={match.rule.id}>
                  <MatchRow
                    match={match}
                    selected={selectedId === match.rule.id}
                    onSelect={() => onSelectRule(match.rule.id)}
                    activeTab={activeTab}
                    onTabChange={onTabChange}
                  />
                </li>
              ))}
            </ul>
          </LanguageGroupHeader>
        ))}
      </div>
      <Footer data={data} />
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

interface MatchRowProps {
  match: RuleMatch;
  selected: boolean;
  onSelect: () => void;
  activeTab: string;
  onTabChange: (key: string) => void;
}

/** A community rule's scan-first row: title, repository, similarity, coverage, severity, updated. */
function MatchRow({ match, selected, onSelect, activeTab, onTabChange }: MatchRowProps) {
  const { rule } = match;

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 overflow-hidden">
      <button
        onClick={onSelect}
        aria-expanded={selected}
        className="w-full flex flex-wrap items-center gap-2 px-3 py-2.5 text-left hover:bg-zinc-800/40 transition-colors"
      >
        <Badge className={matchTypeClass(match.match_type)}>{matchTypeLabel(match.match_type)}</Badge>
        <span className="flex-1 min-w-0 text-sm text-zinc-200 truncate">{rule.name}</span>
        <span className="text-[10px] text-zinc-500">{rule.source.name}</span>
        <span className={`text-xs font-mono ${similarityClass(match.similarity)}`}>
          {match.similarity}% sim
        </span>
        <span className="text-[10px] font-mono text-zinc-500">{match.coverage}% cov</span>
        <Badge className="text-zinc-400 bg-zinc-800/60 border-zinc-700">
          {detectionSeverityLabel(rule.severity)}
        </Badge>
        <span className="hidden sm:inline text-[10px] text-zinc-600">
          {rule.version.updated ?? "—"}
        </span>
        <Chevron expanded={selected} />
      </button>

      {selected && (
        <div className="border-t border-zinc-800 p-3">
          <DetailTabs
            idPrefix={rule.id}
            activeKey={activeTab}
            onChange={onTabChange}
            tabs={buildMatchTabs(match)}
          />
        </div>
      )}
    </div>
  );
}

function buildMatchTabs(match: RuleMatch): DetailTab[] {
  return [
    { key: "overview", label: "Overview", content: <OverviewTab match={match} /> },
    { key: "rule", label: "Rule", content: <RuleTab rule={match.rule} /> },
    { key: "mitre", label: "MITRE", content: <MitreTab rule={match.rule} /> },
    { key: "references", label: "References", content: <ReferencesTab rule={match.rule} /> },
  ];
}

function OverviewTab({ match }: { match: RuleMatch }) {
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
      /* clipboard unavailable — the rule text is still visible in the Rule tab */
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
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px] sm:grid-cols-3">
        <Field label="Repository" value={rule.source.name} />
        <Field label="Author" value={rule.author.name} />
        <Field
          label="License"
          value={`${rule.license.spdx_id} · ${licenseSupportLabel(rule.license.support)}`}
        />
        <Field label="Similarity" value={`${match.similarity}%`} />
        <Field label="Coverage" value={`${match.coverage}%`} />
        <Field label="Language" value={rule.language} mono />
        <Field label="Version" value={`${rule.version.version} (rev ${rule.version.revision})`} />
        <Field label="Updated" value={rule.version.updated ?? "—"} />
      </div>
      {match.rationale && <p className="text-[11px] text-zinc-500">{match.rationale}</p>}
      <div className="flex flex-wrap gap-1.5 pt-1">
        {canShow && (
          <>
            <IconButton label={copied ? "Copied" : "Copy"} onClick={copy} />
            <IconButton label="Download" onClick={download} />
          </>
        )}
        <a
          href={rule.url}
          target="_blank"
          rel="noreferrer noopener"
          className="text-[10px] font-medium text-sky-400 hover:text-sky-300 bg-zinc-800/80 hover:bg-zinc-700 border border-zinc-700 rounded px-2 py-1 transition-colors"
        >
          View Original ↗
        </a>
      </div>
      {!canShow && (
        <p className="text-[10px] text-amber-400/80">
          Rule body withheld under {rule.license.spdx_id}; view the full rule at the source.
        </p>
      )}
    </div>
  );
}

function RuleTab({ rule }: { rule: CommunityRule }) {
  const canShow = isRedistributable(rule.license.support) && rule.content !== null;
  if (!canShow || !rule.content) {
    return (
      <p className="text-xs text-zinc-500">
        This rule&apos;s license ({rule.license.spdx_id}) does not permit redistributing the rule body
        here.{" "}
        <a
          href={rule.url}
          target="_blank"
          rel="noreferrer noopener"
          className="text-sky-400 hover:text-sky-300"
        >
          View it at the source ↗
        </a>
      </p>
    );
  }
  return <CodeViewer content={rule.content} />;
}

function MitreTab({ rule }: { rule: CommunityRule }) {
  if (rule.mitre_techniques.length === 0) {
    return <p className="text-xs text-zinc-500">No ATT&amp;CK mappings for this rule.</p>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {rule.mitre_techniques.map((technique) => (
        <a key={technique} href={mitreTechniqueUrl(technique)} target="_blank" rel="noreferrer noopener">
          <Badge className="text-indigo-300 bg-indigo-500/10 border-indigo-500/30 hover:bg-indigo-500/20">
            {technique}
          </Badge>
        </a>
      ))}
    </div>
  );
}

function ReferencesTab({ rule }: { rule: CommunityRule }) {
  return (
    <div className="space-y-3 text-[11px]">
      <ReferenceGroup label="Repository">
        <ReferenceLink title={rule.source.name} url={rule.source.url} />
        {rule.url !== rule.source.url && <ReferenceLink title="Rule reference" url={rule.url} />}
      </ReferenceGroup>

      {rule.mitre_techniques.length > 0 && (
        <ReferenceGroup label="MITRE references">
          {rule.mitre_techniques.map((technique) => (
            <ReferenceLink key={technique} title={technique} url={mitreTechniqueUrl(technique)} />
          ))}
        </ReferenceGroup>
      )}

      {(rule.author.url || rule.license.url) && (
        <ReferenceGroup label="Vendor references">
          {rule.author.url && <ReferenceLink title={`Author: ${rule.author.name}`} url={rule.author.url} />}
          {rule.license.url && <ReferenceLink title={`License: ${rule.license.spdx_id}`} url={rule.license.url} />}
        </ReferenceGroup>
      )}

      {rule.references.length > 0 && (
        <ReferenceGroup label="External links">
          {rule.references.map((reference, i) => (
            <ReferenceLink key={i} title={reference.title} url={reference.url} />
          ))}
        </ReferenceGroup>
      )}
    </div>
  );
}

function ReferenceGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[9px] uppercase tracking-wider text-zinc-600 mb-1">{label}</p>
      <ul className="space-y-1">{children}</ul>
    </div>
  );
}

function ReferenceLink({ title, url }: { title: string; url: string }) {
  return (
    <li>
      <a href={url} target="_blank" rel="noreferrer noopener" className="text-sky-400 hover:text-sky-300">
        {title}
      </a>
    </li>
  );
}

function Tally({ label, value }: { label: string; value: number }) {
  return (
    <span className="text-[10px] font-mono text-zinc-500">
      {value} {label.toLowerCase()}
    </span>
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
