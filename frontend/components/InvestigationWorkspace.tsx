"use client";

import { useMemo } from "react";

import type { AttributedReference, AttributedRelationship, InvestigationResponse } from "@/lib/api";
import { evidenceByProvider } from "@/lib/investigation";
import { SaveInvestigationButton } from "@/components/workspace/SaveInvestigationButton";

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

interface Props {
  data: InvestigationResponse;
  timestamp: string;
}

export function InvestigationWorkspace({ data, timestamp }: Props) {
  const { entity, threat_intelligence, knowledge, investigation_id } = data;
  const summary = data.investigation_summary;

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
        <div className="flex justify-end">
          <SaveInvestigationButton entity={entity} investigationSummary={summary} />
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

      {/* ── 3. Recommendations (rollup, priority-ordered) ─────────── */}
      {summary && <RecommendationRollup recommendations={summary.recommendations} />}

      {/* ── 4. Findings (primary analyst surface) ─────────────────── */}
      {summary && <FindingsSection findings={summary.findings} />}

      {/* ── 4b. AI explanation (downstream, optional, collapsed) ──── */}
      {summary && <AIExplanationCard summary={summary} />}

      {/* ── 4c. Detection engineering (downstream, optional, collapsed) */}
      {summary && <DetectionEngineeringCard summary={summary} />}

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
          {threat_intelligence.providers.map((provider) => (
            <ProviderCard
              key={provider.provider}
              provider={provider}
              evidence={evidenceByProvider(threat_intelligence.evidence, provider.provider)}
            />
          ))}
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
