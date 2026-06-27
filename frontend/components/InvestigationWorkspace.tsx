"use client";

import { useMemo } from "react";

import type { AttributedReference, AttributedRelationship, InvestigationResponse } from "@/lib/api";
import { evidenceByProvider } from "@/lib/investigation";

import { AdvancedPanel } from "./investigation/AdvancedPanel";
import { InvestigationHeader } from "./investigation/InvestigationHeader";
import { KnowledgeCard } from "./investigation/KnowledgeCard";
import { OverviewCard } from "./investigation/OverviewCard";
import { ProviderCard } from "./investigation/ProviderCard";
import { ReferenceSection } from "./investigation/ReferenceSection";
import { RelationshipSection } from "./investigation/RelationshipSection";
import { ThreatSummaryCard } from "./investigation/ThreatSummaryCard";

interface Props {
  data: InvestigationResponse;
  timestamp: string;
}

export function InvestigationWorkspace({ data, timestamp }: Props) {
  const { entity, threat_intelligence, knowledge, investigation_id } = data;

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
      {/* ── 1. Header ─────────────────────────────────────────────── */}
      <InvestigationHeader
        entity={entity}
        investigationId={investigation_id}
        timestamp={timestamp}
        threatIntelligence={threat_intelligence}
        knowledge={knowledge}
      />

      {/* ── 2. Overview + Key Attributes ──────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <OverviewCard
          entity={entity}
          threatIntelligence={threat_intelligence}
          knowledge={knowledge}
        />
        <div className="lg:col-span-2">
          <ThreatSummaryCard
            entity={entity}
            threatIntelligence={threat_intelligence}
            knowledge={knowledge}
          />
        </div>
      </div>

      {/* ── 3. Threat Intelligence ────────────────────────────────── */}
      {hasTI && (
        <section
          className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3"
          aria-label="Threat Intelligence"
        >
          <h2 className="text-sm font-semibold text-white">Threat Intelligence</h2>
          {threat_intelligence.providers.map((provider) => (
            <ProviderCard
              key={provider.provider}
              provider={provider}
              evidence={evidenceByProvider(threat_intelligence.evidence, provider.provider)}
            />
          ))}
        </section>
      )}

      {/* ── 4. Knowledge ──────────────────────────────────────────── */}
      {hasKB && (
        <section
          className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3"
          aria-label="Knowledge"
        >
          <h2 className="text-sm font-semibold text-white">Knowledge</h2>
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

      {/* ── Fallback when no frameworks have providers ─────────────── */}
      {!hasTI && !hasKB && (
        <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5">
          <p className="text-sm text-zinc-500">
            No providers apply to this entity type yet.
          </p>
        </section>
      )}

      {/* ── 5. Relationships ──────────────────────────────────────── */}
      <RelationshipSection relationships={allRelationships} />

      {/* ── 6. References ─────────────────────────────────────────── */}
      <ReferenceSection references={allReferences} />

      {/* ── 7. Advanced Details ───────────────────────────────────── */}
      <AdvancedPanel threatIntelligence={threat_intelligence} knowledge={knowledge} />
    </div>
  );
}
