"use client";

import { useEffect, useId, useMemo, useState } from "react";
import { useExperiencePreferences, writePreferences } from "@/lib/experiencePreferences";
import type { DetectionPackage } from "@/lib/api";
import { WorkflowStrip } from "./experience/WorkflowStrip";
import { ResultOverview } from "./experience/ResultOverview";

import type { AttributedReference, AttributedRelationship, InvestigationResponse } from "@/lib/api";
import { evidenceByProvider } from "@/lib/investigation";

import { AdvancedPanel } from "./investigation/AdvancedPanel";
import { AIExplanationCard } from "./investigation/AIExplanationCard";
import { DetectionEngineeringCard } from "./investigation/DetectionEngineeringCard";
import { DetectionKnowledgeCard } from "./investigation/DetectionKnowledgeCard";
import { FindingsSection } from "./investigation/FindingsSection";
import { InvestigationHeader } from "./investigation/InvestigationHeader";
import { InvestigationSummaryCard } from "./investigation/InvestigationSummaryCard";
import { KnowledgeCard } from "./investigation/KnowledgeCard";
import { OverviewCard } from "./investigation/OverviewCard";
import { ProviderCard } from "./investigation/ProviderCard";
import { RecommendationRollup } from "./investigation/RecommendationRollup";
import { ReferenceSection } from "./investigation/ReferenceSection";
import { RelationshipSection } from "./investigation/RelationshipSection";
import { ThreatSummaryCard } from "./investigation/ThreatSummaryCard";
import { ContextSignalsCard } from "./investigation/ContextSignalsCard";
import { RelatedExpansion } from "./investigation/RelatedExpansion";

interface Props {
  data: InvestigationResponse;
  timestamp: string;
  onInvestigateRelated?: (query: string) => void;
  savedId?: string | null;
  onSaved?: (id: string) => void;
  packageValue?: DetectionPackage;
  onPackage?: (pkg: DetectionPackage) => void;
}

export function InvestigationWorkspace({ data, timestamp, onInvestigateRelated, savedId, onSaved, packageValue, onPackage }: Props) {
  const scope = useId();
  const [localPackage, setPackage] = useState<DetectionPackage | null>(null);
  const pkg = packageValue ?? localPackage;
  const [generationSignal, setGenerationSignal] = useState(0);
  const preferences = useExperiencePreferences();
  useEffect(() => { setPackage(null); }, [data.investigation_id]);
  const { entity, threat_intelligence, knowledge, investigation_id } = data;
  const summary = data.investigation_summary;
  function rememberSection(section: string, open: boolean) {
    if (open === !preferences.collapsed.includes(section)) return;
    writePreferences({ collapsed: open ? preferences.collapsed.filter((s) => s !== section) : [...new Set([...preferences.collapsed, section])] });
  }
  const { exposure, correlation } = data;

  const hasTI = threat_intelligence.providers.length > 0;
  const hasKB = knowledge.providers.length > 0;

  // Merged, deduplicated relationships across both frameworks
  const allRelationships = useMemo<AttributedRelationship[]>(() => {
    const seen = new Set<string>();
    return [...threat_intelligence.relationships, ...knowledge.relationships].filter((r) => {
      const key = `${r.relationship.relationship}:${r.relationship.target_type}:${r.relationship.target_value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [threat_intelligence.relationships, knowledge.relationships]);

  // Merged, deduplicated references across both frameworks
  const allReferences = useMemo<AttributedReference[]>(() => {
    const seen = new Set<string>();
    return [...threat_intelligence.references, ...knowledge.references].filter((r) => {
      const key = r.reference.url.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [threat_intelligence.references, knowledge.references]);

  return (
    <div className="w-full space-y-4 text-left" role="main" aria-label="Investigation workspace">
      {/* ── 0. Save to Workspace (Phase 8.0 — persistence, separate from search) ── */}
      {summary && (
        <div className="w-full">
          <WorkflowStrip data={data} pkg={pkg} savedId={savedId} onSaved={onSaved} generate={() => setGenerationSignal((s) => s + 1)} />
        </div>
      )}

      {/* ── 1. Header ─────────────────────────────────────────────── */}
      <InvestigationHeader
        entity={entity}
        investigationId={investigation_id}
        timestamp={timestamp}
        threatIntelligence={threat_intelligence}
        knowledge={knowledge}
      />

      {/* ── Investigation Results (analyst workflow) ──────────────── */}
      <SectionDivider label="Investigation Results" />

      {/* ── 2. Investigation assessment (reasoning headline) ──────── */}
      {summary && <InvestigationSummaryCard summary={summary} />}
      {summary && <details open={!preferences.collapsed.includes("assessment")} onToggle={(event) => rememberSection("assessment", event.currentTarget.open)}><summary className="cursor-pointer text-xs text-zinc-400">Assessment overview</summary><ResultOverview data={data} summary={summary} scope={scope} /></details>}

      <ProviderAgreementCard result={threat_intelligence} />

      <ContextSignalsCard exposure={exposure} correlation={correlation} />
      <RelatedExpansion entity={entity} relationships={allRelationships} onInvestigate={onInvestigateRelated} />

      {/* ── 3. Recommendations (rollup, priority-ordered) ─────────── */}
      {summary && <div id={`${scope}-recommendations`}><RecommendationRollup recommendations={summary.recommendations} /></div>}

      {/* ── 4. Findings (primary analyst surface) ─────────────────── */}
      {summary && <div id={`${scope}-findings`}><FindingsSection findings={summary.findings} /></div>}

      {/* ── 4b. AI explanation (downstream, optional, collapsed) ──── */}
      {summary && <AIExplanationCard summary={summary} />}

      {/* ── 4c. Detection engineering (downstream, optional, collapsed) */}
      {summary && <DetectionEngineeringCard summary={summary} packageValue={pkg} onPackage={(value) => { setPackage(value); onPackage?.(value); }} generationSignal={generationSignal} />}

      {/* ── 4d. Detection knowledge — COMMUNITY detections (separate) ── */}
      {summary && <DetectionKnowledgeCard summary={summary} />}

      {/* ── Supporting Investigation Data (visual grouping only) ──── */}
      <SectionDivider label="Supporting Investigation Data" />

      {/* ── 5. Entity context + key attributes ────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <OverviewCard
          entity={entity}
          threatIntelligence={threat_intelligence}
          knowledge={knowledge}
          relationshipCount={allRelationships.length}
          referenceCount={allReferences.length}
          timestamp={timestamp}
        />
        <div className="lg:col-span-2">
          <ThreatSummaryCard
            entity={entity}
            threatIntelligence={threat_intelligence}
            knowledge={knowledge}
          />
        </div>
      </div>

      {/* ── 6. Provider details (supporting) — Threat Intelligence ── */}
      {hasTI && (
        <section
          className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-2.5"
          aria-label="Threat Intelligence"
        >
          <h2 className="text-sm font-semibold text-white">
            Threat Intelligence
            <span className="ml-2 text-xs font-normal text-zinc-500">
              ({threat_intelligence.providers.length})
            </span>
          </h2>
          <details open={!preferences.collapsed.includes("providers")} onToggle={(event) => rememberSection("providers", event.currentTarget.open)}><summary className="cursor-pointer text-xs text-zinc-500">Provider evidence details</summary>
          {threat_intelligence.providers.map((provider) => (
            <ProviderCard
              key={provider.provider}
              provider={provider}
              evidence={evidenceByProvider(threat_intelligence.evidence, provider.provider)}
            />
          ))}</details>
        </section>
      )}

      {/* ── 7. Provider details (supporting) — Knowledge ──────────── */}
      {hasKB && (
        <section
          className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-2.5"
          aria-label="Knowledge"
        >
          <h2 className="text-sm font-semibold text-white">
            Knowledge
            <span className="ml-2 text-xs font-normal text-zinc-500">
              ({knowledge.providers.length})
            </span>
          </h2>
          {knowledge.providers.map((provider) => (
            <KnowledgeCard
              key={provider.provider}
              provider={provider}
              evidence={evidenceByProvider(knowledge.evidence, provider.provider)}
              metadata={knowledge.metadata[provider.provider]}
            />
          ))}
        </section>
      )}

      {/* ── 8. Relationships ──────────────────────────────────────── */}
      <RelationshipSection relationships={allRelationships} />

      {/* ── 9. References ─────────────────────────────────────────── */}
      <ReferenceSection references={allReferences} />

      {/* ── 10. Advanced Details ──────────────────────────────────── */}
      <AdvancedPanel threatIntelligence={threat_intelligence} knowledge={knowledge} />
    </div>
  );
}

function ProviderAgreementCard({ result }: { result: InvestigationResponse["threat_intelligence"] }) {
  const agreement = result.agreement;
  if (!agreement) return null;
  const counts = [
    ["Malicious", agreement.malicious, "text-red-300"],
    ["Suspicious", agreement.suspicious, "text-amber-300"],
    ["Benign", agreement.benign, "text-emerald-300"],
    ["Unknown", agreement.unknown, "text-zinc-300"],
    ["No data", agreement.no_data, "text-zinc-400"],
    ["Failed", agreement.failures, "text-red-300"],
  ] as const;
  return (
    <section className="rounded-2xl border border-zinc-800 bg-zinc-900 p-5" aria-label="Provider agreement">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div><h2 className="text-sm font-semibold text-white">Provider agreement</h2><p className="mt-1 text-xs text-zinc-500">Verdicts are separate from missing data and provider failures.</p></div>
        {agreement.conflicted && <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-xs text-amber-300">Conflicting verdicts</span>}
      </div>
      <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-6">
        {counts.map(([label, value, color]) => <div key={label} className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><p className={`text-lg font-semibold ${color}`}>{value}</p><p className="text-xs text-zinc-500">{label}</p></div>)}
      </div>
    </section>
  );
}

/** A lightweight eyebrow + rule dividing the page into its two visual zones
 * (Investigation Results / Supporting Investigation Data). Grouping only —
 * it changes no layout, order, or functionality of the sections it separates. */
function SectionDivider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 pt-2" role="separator" aria-label={label}>
      <span className="text-[11px] font-semibold text-zinc-600 uppercase tracking-widest whitespace-nowrap">
        {label}
      </span>
      <div className="h-px flex-1 bg-zinc-800" aria-hidden />
    </div>
  );
}
