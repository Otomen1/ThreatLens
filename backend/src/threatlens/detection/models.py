"""Canonical models for the Detection Engineering Framework (Phase 4.0).

Frozen, fully-typed contracts mirroring the design quality of
``reasoning.models``. A :class:`DetectionPackage` is the framework's output — a
downstream, deterministic *view* of an :class:`~threatlens.reasoning.models.InvestigationSummary`.

The Detection Engine is a pure consumer. Nothing here influences findings,
confidence, severity, priority, recommendations, or relationships: severities are
**copied** from the summary (value-aligned enum), never recomputed. All models
are immutable; sequence fields are tuples so a package cannot be mutated after
construction.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ..entities.types import EntityType
from .types import (
    DetectionCapability,
    DetectionCategory,
    DetectionLanguage,
    DetectionSeverity,
    DetectionValidationStatus,
)

# --------------------------------------------------------------------------- #
# Leaf models
# --------------------------------------------------------------------------- #


class DetectionReference(BaseModel):
    """A citation supporting a detection (MITRE technique, CVE, vendor doc, …)."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    url: str | None = None
    description: str | None = None


class DetectionTarget(BaseModel):
    """Where an artifact is meant to run: a language plus an optional platform.

    ``platform``/``product`` describe the destination SIEM/EDR (e.g. ``splunk``,
    ``"Microsoft Sentinel"``); ``generic`` means language-native / portable.
    """

    model_config = ConfigDict(frozen=True)

    language: DetectionLanguage
    platform: str = "generic"
    product: str | None = None


class DetectionValidation(BaseModel):
    """The result of validating an artifact against its toolchain.

    ``UNVALIDATED`` in this phase — validators are extension points only.
    """

    model_config = ConfigDict(frozen=True)

    status: DetectionValidationStatus = DetectionValidationStatus.UNVALIDATED
    validator: str | None = None
    messages: tuple[str, ...] = ()


class DetectionTemplate(BaseModel):
    """A reusable blueprint a generator instantiates into an artifact.

    Templates carry no rule text of their own; they fix the language, target, and
    category so every artifact of a kind is shaped and identified consistently.
    The template set is empty in this phase.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    language: DetectionLanguage
    target: DetectionTarget
    category: DetectionCategory = DetectionCategory.GENERIC
    description: str = ""
    capabilities: frozenset[DetectionCapability] = frozenset()


# --------------------------------------------------------------------------- #
# Artifact
# --------------------------------------------------------------------------- #


class DetectionArtifact(BaseModel):
    """A single generated detection.

    ``id`` is deterministic and content-addressed (see
    ``detection.engine.compute_artifact_id``): it hashes only stable values —
    never timestamps, never AI output. ``content`` is the rule text and is empty
    until a concrete generator (later phase) fills it. ``severity`` is copied from
    the originating finding, never recomputed.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    language: DetectionLanguage
    target: DetectionTarget
    title: str = Field(min_length=1)
    description: str = ""
    content: str = ""
    severity: DetectionSeverity = DetectionSeverity.INFORMATIONAL
    category: DetectionCategory = DetectionCategory.GENERIC
    capabilities: frozenset[DetectionCapability] = frozenset()
    source_finding_ids: tuple[str, ...] = ()
    references: tuple[DetectionReference, ...] = ()
    validation: DetectionValidation = DetectionValidation()
    rule_id: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Package (top-level engine output)
# --------------------------------------------------------------------------- #


class DetectionMetadata(BaseModel):
    """Provenance for a package: what produced it, from which summary.

    ``generated_at`` is inherited from the source ``InvestigationSummary`` (the
    engine never reads the wall clock), keeping generation a pure function of its
    input. ``source_*`` fields are copied from the summary for context only.
    """

    model_config = ConfigDict(frozen=True)

    engine_version: str
    source_engine_version: str
    entity_type: EntityType
    entity_value: str
    generated_at: datetime
    source_finding_count: int = Field(default=0, ge=0)
    source_posture: DetectionSeverity = DetectionSeverity.INFORMATIONAL


class DetectionPackage(BaseModel):
    """The Detection Engine's output for one investigation.

    ``id`` is content-addressed and stable across runs (timestamp-independent).
    ``artifacts`` is empty in this phase (no generators are registered); the shape
    is final so the API and UI already understand a fully-populated package.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    metadata: DetectionMetadata
    artifacts: tuple[DetectionArtifact, ...] = ()
    languages: tuple[DetectionLanguage, ...] = ()
    references: tuple[DetectionReference, ...] = ()
    source_finding_ids: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """True when no detection artifacts were generated."""
        return not self.artifacts
