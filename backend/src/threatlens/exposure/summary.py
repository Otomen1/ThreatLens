"""Builds the canonical :class:`ExposureSummary` from per-provider findings.

Mirrors ``providers/aggregation.py``: merges many providers' findings for one
entity into one summary, de-duplicating assets and references while keeping
every provider's attribution (including ones that found nothing or failed —
one provider's absence of data or error never drops another's). Performs no
scoring and makes no exposure "severity" judgment; that is out of scope for
this framework entirely.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from ..entities.types import EntityType
from .models import (
    ExposureAsset,
    ExposureFinding,
    ExposureMetadata,
    ExposureReference,
    ExposureStatistics,
    ExposureSummary,
)


def merge_findings(
    findings: Sequence[ExposureFinding],
    *,
    entity_type: EntityType,
    entity_value: str,
    framework_version: str,
    now: datetime | None = None,
) -> ExposureSummary:
    """Merge per-provider findings for one entity into an :class:`ExposureSummary`.

    An empty ``findings`` sequence (Phase 5.0's only real case, since zero
    providers are registered) yields a well-formed, empty summary — the same
    code path a future non-empty call uses.
    """
    generated_at = now or datetime.now(UTC)
    with_data = [f for f in findings if f.has_findings]

    statistics = ExposureStatistics(
        providers_queried=len(findings),
        providers_ok=sum(1 for f in findings if f.is_ok),
        total_findings=len(with_data),
        total_assets=sum(len(f.assets) for f in findings),
        categories=frozenset(f.category for f in with_data if f.category is not None),
    )

    return ExposureSummary(
        entity_type=entity_type,
        entity_value=entity_value,
        findings=list(findings),
        references=_merge_references(findings),
        statistics=statistics,
        metadata=ExposureMetadata(
            entity_type=entity_type,
            entity_value=entity_value,
            generated_at=generated_at,
            framework_version=framework_version,
        ),
    )


def _merge_references(findings: Sequence[ExposureFinding]) -> list[ExposureReference]:
    """De-duplicate references across providers by URL (first occurrence wins)."""
    seen: dict[str, ExposureReference] = {}
    for finding in findings:
        for reference in finding.references:
            key = reference.url.strip().lower()
            seen.setdefault(key, reference)
    return list(seen.values())


def merge_assets(findings: Sequence[ExposureFinding]) -> list[ExposureAsset]:
    """De-duplicate assets across providers by ``(asset_type, value)``.

    Not used by :func:`merge_findings` (assets stay attached to their
    reporting finding for provenance) — offered for a future consumer that
    wants one flat, deduplicated asset list across all providers.
    """
    seen: dict[tuple[str, str], ExposureAsset] = {}
    for finding in findings:
        for asset in finding.assets:
            key = (asset.asset_type, asset.value.strip().lower())
            seen.setdefault(key, asset)
    return list(seen.values())
