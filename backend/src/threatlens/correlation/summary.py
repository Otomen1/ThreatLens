"""Builds the canonical :class:`CorrelationSummary` from raw observations.

Mirrors ``exposure/summary.py``'s aggregation split: the engine
(``engine.py``) evaluates rules into observations; this module deterministically
orders and de-duplicates them, groups them into per-rule matches, computes
statistics, assigns the content-addressed summary id, and stamps metadata. It
owns the summary id (``compute_summary_id``) so ``engine.py`` depends on it and
not vice-versa (no import cycle).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from datetime import datetime

from ..entities.types import EntityType
from .models import (
    CorrelationMatch,
    CorrelationMetadata,
    CorrelationObservation,
    CorrelationStatistics,
    CorrelationSummary,
)


def compute_summary_id(
    *,
    entity_type: EntityType,
    entity_value: str,
    source_engine_version: str,
    observation_ids: Iterable[str],
) -> str:
    """Deterministic, content-addressed summary id.

    Hashes the entity, the source engine version, and the sorted observation
    ids — never ``generated_at`` — so re-running correlation on the same
    investigation always yields the same id.
    """
    ids = sorted({oid.strip() for oid in observation_ids if oid.strip()})
    payload = "|".join(
        [entity_type.value, entity_value.strip().lower(), source_engine_version, *ids]
    )
    return f"cors_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def _ordered(observations: Sequence[CorrelationObservation]) -> tuple[CorrelationObservation, ...]:
    """Deterministic observation order: category, subject, then content id."""
    return tuple(
        sorted(
            observations,
            key=lambda o: (o.category.value, o.subject_type.value, o.subject_value.lower(), o.id),
        )
    )


def _dedupe(observations: Sequence[CorrelationObservation]) -> list[CorrelationObservation]:
    """Drop observations sharing a content-addressed id (first occurrence wins)."""
    seen: set[str] = set()
    out: list[CorrelationObservation] = []
    for observation in observations:
        if observation.id not in seen:
            seen.add(observation.id)
            out.append(observation)
    return out


def _matches(observations: Sequence[CorrelationObservation]) -> tuple[CorrelationMatch, ...]:
    """Group observations into per-rule execution records, ordered by rule id."""
    by_rule: dict[str, list[CorrelationObservation]] = {}
    for observation in observations:
        by_rule.setdefault(observation.rule_id, []).append(observation)
    return tuple(
        CorrelationMatch(
            rule_id=rule_id,
            category=obs[0].category,
            observation_ids=tuple(sorted(o.id for o in obs)),
        )
        for rule_id, obs in sorted(by_rule.items())
    )


def build_correlation_summary(
    observations: Sequence[CorrelationObservation],
    *,
    entity_type: EntityType,
    entity_value: str,
    source_engine_version: str,
    source_finding_ids: Sequence[str],
    framework_version: str,
    generated_at: datetime,
    rules_evaluated: int,
) -> CorrelationSummary:
    """Merge raw observations into a well-formed :class:`CorrelationSummary`.

    An empty ``observations`` sequence yields a well-formed empty summary — the
    same code path a non-empty call uses.
    """
    unique = _ordered(_dedupe(observations))
    matches = _matches(unique)

    statistics = CorrelationStatistics(
        rules_evaluated=rules_evaluated,
        rules_matched=len(matches),
        total_observations=len(unique),
        source_finding_count=len(source_finding_ids),
        categories=frozenset(o.category for o in unique),
    )
    summary_id = compute_summary_id(
        entity_type=entity_type,
        entity_value=entity_value,
        source_engine_version=source_engine_version,
        observation_ids=[o.id for o in unique],
    )
    return CorrelationSummary(
        id=summary_id,
        entity_type=entity_type,
        entity_value=entity_value,
        observations=unique,
        matches=matches,
        statistics=statistics,
        metadata=CorrelationMetadata(
            entity_type=entity_type,
            entity_value=entity_value,
            generated_at=generated_at,
            framework_version=framework_version,
            source_engine_version=source_engine_version,
        ),
        source_finding_ids=tuple(source_finding_ids),
    )
