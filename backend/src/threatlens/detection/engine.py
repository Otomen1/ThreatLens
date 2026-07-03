"""The Detection Engine — a pure, deterministic consumer of InvestigationSummary.

``generate(summary)`` converts a completed
:class:`~threatlens.reasoning.models.InvestigationSummary` into a
:class:`~threatlens.detection.models.DetectionPackage` by running every
registered :class:`~threatlens.detection.registry.DetectionGenerator`. In this
phase the default registry is empty, so the package carries metadata but no
artifacts.

Guarantees (mirroring the Reasoning Engine):

* **Pure.** No I/O, no providers, no AI, no wall clock — ``generated_at`` is
  inherited from the summary, so identical input always yields an identical
  package.
* **Read-only.** The summary is consumed, never mutated. Findings, confidence,
  severity, priority, recommendations, and relationships are untouched; severity
  is copied, never recomputed.
* **Content-addressed identity.** Artifact and package ids hash only stable
  values — never timestamps, never AI output — so the same evidence always maps
  to the same id.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from ..reasoning import InvestigationSummary
from .models import (
    DetectionArtifact,
    DetectionMetadata,
    DetectionPackage,
    DetectionReference,
)
from .registry import DetectionRegistry, build_default_registry
from .types import DetectionCategory, DetectionLanguage, DetectionSeverity

DETECTION_ENGINE_VERSION = "1.0"
"""Frozen Detection Engine version (Phase 4.5). Like the Reasoning Engine, changes
to generator output must regenerate the golden snapshots and bump this version."""


# --------------------------------------------------------------------------- #
# Identity (stable, content-addressed — never includes timestamps or AI output)
# --------------------------------------------------------------------------- #


def compute_artifact_id(
    *,
    language: DetectionLanguage,
    target_platform: str,
    category: DetectionCategory,
    content: str,
    rule_id: str | None,
    source_finding_ids: Iterable[str],
) -> str:
    """Deterministic, content-addressed artifact id.

    Hashes language, target platform, category, the (stripped) rule content, an
    optional generator rule id, and the sorted source finding ids. Excludes
    timestamps, ordering, and AI. The same detection therefore always yields the
    same id.
    """
    identities = sorted({fid.strip().lower() for fid in source_finding_ids if fid.strip()})
    payload = "|".join(
        [
            language.value,
            target_platform.strip().lower(),
            category.value,
            (rule_id or "").strip().lower(),
            content.strip(),
            *identities,
        ]
    )
    return f"det_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def compute_package_id(
    *,
    entity_type: str,
    entity_value: str,
    source_engine_version: str,
    artifact_ids: Iterable[str],
    source_finding_ids: Iterable[str],
) -> str:
    """Deterministic package id over the entity, source engine, and stable ids.

    Excludes ``generated_at`` so re-running detection on the same investigation
    (even at a different time) yields the same package id.
    """
    artifacts = sorted({aid.strip() for aid in artifact_ids if aid.strip()})
    findings = sorted({fid.strip() for fid in source_finding_ids if fid.strip()})
    payload = "|".join(
        [
            entity_type,
            entity_value.strip().lower(),
            source_engine_version,
            "artifacts",
            *artifacts,
            "findings",
            *findings,
        ]
    )
    return f"pkg_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #


def generate(
    summary: InvestigationSummary,
    *,
    registry: DetectionRegistry | None = None,
) -> DetectionPackage:
    """Convert an ``InvestigationSummary`` into a ``DetectionPackage`` (pure).

    Runs each registered generator, orders the artifacts deterministically, and
    wraps them with content-addressed identity and inherited provenance. With the
    default (empty) registry the result is a well-formed, artifact-free package.
    """
    reg = registry if registry is not None else build_default_registry()

    artifacts: list[DetectionArtifact] = []
    for generator in reg.generators:
        artifacts.extend(generator.generate(summary))
    artifacts = _ordered(artifacts)

    source_finding_ids = tuple(finding.id for finding in summary.findings)
    metadata = DetectionMetadata(
        engine_version=DETECTION_ENGINE_VERSION,
        source_engine_version=summary.engine_version,
        entity_type=summary.entity_type,
        entity_value=summary.entity_value,
        generated_at=summary.generated_at,  # inherited — the engine never reads the clock
        source_finding_count=len(summary.findings),
        source_posture=DetectionSeverity(int(summary.posture)),
    )
    package_id = compute_package_id(
        entity_type=summary.entity_type.value,
        entity_value=summary.entity_value,
        source_engine_version=summary.engine_version,
        artifact_ids=[artifact.id for artifact in artifacts],
        source_finding_ids=source_finding_ids,
    )
    return DetectionPackage(
        id=package_id,
        metadata=metadata,
        artifacts=tuple(artifacts),
        languages=_languages(artifacts),
        references=_dedupe_references(artifacts),
        source_finding_ids=source_finding_ids,
    )


def _ordered(artifacts: list[DetectionArtifact]) -> list[DetectionArtifact]:
    """Deterministic artifact order: most severe first, then language, then id."""
    return sorted(artifacts, key=lambda a: (-int(a.severity), a.language.value, a.id))


def _languages(artifacts: Iterable[DetectionArtifact]) -> tuple[DetectionLanguage, ...]:
    return tuple(sorted({a.language for a in artifacts}, key=lambda lang: lang.value))


def _dedupe_references(
    artifacts: Iterable[DetectionArtifact],
) -> tuple[DetectionReference, ...]:
    """Unique references across all artifacts, in first-seen order."""
    seen: set[tuple[str, str | None]] = set()
    out: list[DetectionReference] = []
    for artifact in artifacts:
        for reference in artifact.references:
            key = (reference.title, reference.url)
            if key not in seen:
                seen.add(key)
                out.append(reference)
    return tuple(out)
