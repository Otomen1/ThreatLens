"""The Intelligence Aggregation Engine.

Combines many per-provider :class:`IntelligenceResult` objects for one entity
into a single canonical :class:`AggregatedResult`: per-provider attribution and
status, each provider's (unscored) reputation, and merged, de-duplicated
evidence / relationships / references / tags — with the set of providers that
contributed each item preserved.

It performs no scoring and makes no malicious/benign decision. A failed provider
contributes its status (so the UI can surface it) but no findings; one provider
failing never drops another's data. The per-provider models stay clean — item
attribution lives here, in thin wrappers, not on the shared result contract.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from ..entities.types import EntityType
from .results import (
    Evidence,
    IntelligenceResult,
    Reference,
    Relationship,
    Reputation,
    ResultError,
    ResultStatus,
)

# Only these states carry findings worth merging; everything else is attribution
# (the provider ran, here is what happened) but contributes no data.
_FINDING_STATES = frozenset({ResultStatus.OK, ResultStatus.PARTIAL})


class ProviderSummary(BaseModel):
    """Attribution and outcome for one provider that participated."""

    model_config = ConfigDict(frozen=True)

    provider: str
    provider_display_name: str | None = None
    status: ResultStatus
    reputation: Reputation | None = None
    error: ResultError | None = None


class AttributedEvidence(BaseModel):
    """One de-duplicated evidence record and the providers that reported it."""

    model_config = ConfigDict(frozen=True)

    evidence: Evidence
    sources: list[str]


class AttributedRelationship(BaseModel):
    """One de-duplicated relationship and the providers that reported it."""

    model_config = ConfigDict(frozen=True)

    relationship: Relationship
    sources: list[str]


class AttributedReference(BaseModel):
    """One de-duplicated reference and the providers that reported it."""

    model_config = ConfigDict(frozen=True)

    reference: Reference
    sources: list[str]


class AggregatedResult(BaseModel):
    """Every provider's intelligence about one entity, merged and attributed."""

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    providers: list[ProviderSummary] = Field(default_factory=list)
    evidence: list[AttributedEvidence] = Field(default_factory=list)
    relationships: list[AttributedRelationship] = Field(default_factory=list)
    references: list[AttributedReference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @property
    def provider_count(self) -> int:
        """How many providers participated."""
        return len(self.providers)

    @property
    def succeeded(self) -> list[str]:
        """Names of providers that returned data successfully."""
        return [p.provider for p in self.providers if p.status is ResultStatus.OK]

    @property
    def has_findings(self) -> bool:
        """True when any provider contributed intelligence."""
        return bool(
            self.evidence
            or self.relationships
            or self.references
            or any(p.reputation for p in self.providers)
        )


def aggregate(
    results: Sequence[IntelligenceResult],
    *,
    entity_type: EntityType,
    entity_value: str,
) -> AggregatedResult:
    """Merge per-provider results for one entity into an :class:`AggregatedResult`.

    Every result becomes a :class:`ProviderSummary` (attribution + status); only
    successful/partial results contribute findings. Evidence, relationships, and
    references are de-duplicated across providers while preserving the set of
    contributing providers; metadata is namespaced per provider to avoid clashes.
    """
    contributing = [r for r in results if r.status in _FINDING_STATES]
    return AggregatedResult(
        entity_type=entity_type,
        entity_value=entity_value,
        providers=[_summarize(r) for r in results],
        evidence=_merge_evidence(contributing),
        relationships=_merge_relationships(contributing),
        references=_merge_references(contributing),
        tags=_merge_tags(contributing),
        metadata=_merge_metadata(contributing),
    )


def _summarize(result: IntelligenceResult) -> ProviderSummary:
    return ProviderSummary(
        provider=result.provider,
        provider_display_name=result.provider_display_name,
        status=result.status,
        reputation=result.reputation,
        error=result.error,
    )


def _merge_evidence(results: Sequence[IntelligenceResult]) -> list[AttributedEvidence]:
    merged: dict[tuple[str, str], tuple[Evidence, list[str]]] = {}
    for result in results:
        for evidence in result.evidence:
            identity = (evidence.value or evidence.summary).strip().lower()
            key = (evidence.type.value, identity)
            _accumulate(merged, key, evidence, result.provider)
    return [AttributedEvidence(evidence=item, sources=sources) for item, sources in merged.values()]


def _merge_relationships(
    results: Sequence[IntelligenceResult],
) -> list[AttributedRelationship]:
    merged: dict[tuple[str, str, str], tuple[Relationship, list[str]]] = {}
    for result in results:
        for relationship in result.relationships:
            key = (
                relationship.relationship.value,
                relationship.target_type.value,
                relationship.target_value.strip().lower(),
            )
            _accumulate(merged, key, relationship, result.provider)
    return [
        AttributedRelationship(relationship=item, sources=sources)
        for item, sources in merged.values()
    ]


def _merge_references(results: Sequence[IntelligenceResult]) -> list[AttributedReference]:
    merged: dict[str, tuple[Reference, list[str]]] = {}
    for result in results:
        for reference in result.references:
            key = reference.url.strip().lower()
            _accumulate(merged, key, reference, result.provider)
    return [
        AttributedReference(reference=item, sources=sources) for item, sources in merged.values()
    ]


def _merge_tags(results: Sequence[IntelligenceResult]) -> list[str]:
    seen: dict[str, str] = {}
    for result in results:
        for tag in result.tags:
            normalized = tag.strip().lower()
            if normalized and normalized not in seen:
                seen[normalized] = tag.strip()
    return list(seen.values())


def _merge_metadata(results: Sequence[IntelligenceResult]) -> dict[str, JsonValue]:
    # Namespace by provider so providers can never clobber each other's keys.
    return {result.provider: dict(result.metadata) for result in results if result.metadata}


_K = TypeVar("_K")
_V = TypeVar("_V")


def _accumulate(
    merged: dict[_K, tuple[_V, list[str]]],
    key: _K,
    item: _V,
    provider: str,
) -> None:
    """Insert ``item`` under ``key`` (first wins), recording ``provider`` once."""
    existing = merged.get(key)
    if existing is None:
        merged[key] = (item, [provider])
    elif provider not in existing[1]:
        existing[1].append(provider)
