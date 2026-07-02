"""The EvidenceAssembler — deterministic normalization, no scoring.

Takes the two existing aggregation outputs (threat-intelligence and knowledge)
and normalizes them into one weighted evidence ledger, preserving attribution,
timestamps, relationships, and references. It assigns each item a deterministic
weight/polarity/dimension from the static tables in :mod:`.config`; it computes
no confidence, no findings, no recommendations, and never touches the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..providers.aggregation import (
    AggregatedResult,
    AttributedEvidence,
    AttributedReference,
    AttributedRelationship,
    ProviderSummary,
)
from ..providers.results import Evidence, EvidenceType, ReputationLevel
from . import config
from .models import EvidenceDimension, WeightedEvidence


@dataclass(frozen=True)
class EvidenceLedger:
    """The assembler's output: weighted evidence plus preserved graph context."""

    evidence: tuple[WeightedEvidence, ...]
    relationships: tuple[AttributedRelationship, ...]
    references: tuple[AttributedReference, ...]


class EvidenceAssembler:
    """Normalizes aggregated TI + knowledge into a weighted evidence ledger."""

    def assemble(
        self,
        ti: AggregatedResult,
        knowledge: AggregatedResult,
        *,
        now: datetime,
    ) -> EvidenceLedger:
        """Build the deterministic ledger from both aggregation frameworks."""
        weighted: list[WeightedEvidence] = []
        for aggregated in (ti, knowledge):
            for attributed in aggregated.evidence:
                weighted.append(self._weigh_evidence(attributed, now))
            for summary in aggregated.providers:
                lifted = self._lift_reputation(summary, now)
                if lifted is not None:
                    weighted.append(lifted)

        relationships = (*ti.relationships, *knowledge.relationships)
        references = (*ti.references, *knowledge.references)
        return EvidenceLedger(
            evidence=tuple(weighted),
            relationships=relationships,
            references=references,
        )

    # --- per-item normalization ------------------------------------------- #

    @staticmethod
    def _weigh_evidence(attributed: AttributedEvidence, now: datetime) -> WeightedEvidence:
        evidence_type = attributed.evidence.type
        weight = (
            config.base_weight(evidence_type)
            * config.max_authority(attributed.sources)
            * config.freshness(attributed.evidence.observed_at, now)
        )
        return WeightedEvidence(
            evidence=attributed,
            weight=_clamp(weight),
            polarity=config.polarity_for(evidence_type),
            dimension=config.dimension_for(evidence_type),
        )

    @staticmethod
    def _lift_reputation(summary: ProviderSummary, now: datetime) -> WeightedEvidence | None:
        """Lift a provider's reputation verdict into reputation-dimension evidence."""
        reputation = summary.reputation
        if reputation is None or reputation.level is ReputationLevel.UNKNOWN:
            return None

        level = reputation.level
        weight = config.REPUTATION_WEIGHT[level] * config.authority_of(summary.provider).authority
        synthesized = Evidence(
            type=EvidenceType.OTHER,
            summary=f"Reputation: {level.value} ({summary.provider})",
            value=level.value,
            confidence=reputation.score,
        )
        return WeightedEvidence(
            evidence=AttributedEvidence(evidence=synthesized, sources=[summary.provider]),
            weight=_clamp(weight),
            polarity=config.REPUTATION_POLARITY[level],
            dimension=EvidenceDimension.REPUTATION,
        )


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
