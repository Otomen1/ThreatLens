"""Deterministic builders for reporting tests.

A minimal, self-contained factory — mirroring ``tests/graph/factories.py``'s
and ``tests/timeline/factories.py``'s own shape for the parts this package
needs. ``ReportService`` has almost no derivation logic of its own (it
composes ``TimelineService``/``GraphService``, both already exhaustively
tested in their own suites), so these tests focus on composition,
determinism, and non-mutation rather than re-testing event/node derivation.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from threatlens.entities.types import EntityType
from threatlens.reasoning.models import (
    Confidence,
    ConfidenceBand,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Severity,
)
from threatlens.workspace import WorkspaceInvestigation

NOW = datetime(2024, 1, 1, tzinfo=UTC)
_CONFIDENCE = Confidence(score=80, band=ConfidenceBand.HIGH)


def finding(fid: str, **overrides: Any) -> Finding:
    """Build a minimal, valid :class:`Finding`."""
    defaults: dict[str, Any] = {
        "id": fid,
        "title": f"{fid} title",
        "categories": frozenset({FindingCategory.MALICIOUS_INFRASTRUCTURE}),
        "subject_type": EntityType.IPV4,
        "subject_value": "8.8.8.8",
        "severity": Severity.HIGH,
        "confidence": _CONFIDENCE,
    }
    defaults.update(overrides)
    return Finding(**defaults)


def summary(findings: Iterable[Finding] = (), **overrides: Any) -> InvestigationSummary:
    """Build a minimal, valid :class:`InvestigationSummary` around ``findings``."""
    defaults: dict[str, Any] = {
        "entity_type": EntityType.IPV4,
        "entity_value": "8.8.8.8",
        "posture": Severity.HIGH,
        "overall_confidence": _CONFIDENCE,
        "categories": frozenset(),
        "findings": list(findings),
        "engine_version": "1.0",
        "generated_at": NOW,
    }
    defaults.update(overrides)
    return InvestigationSummary(**defaults)


def record(**overrides: Any) -> WorkspaceInvestigation:
    """Build a minimal, valid :class:`WorkspaceInvestigation`."""
    defaults: dict[str, Any] = {
        "id": uuid4(),
        "title": "Case",
        "created_at": NOW,
        "updated_at": NOW,
        "investigation_type": EntityType.IPV4,
    }
    defaults.update(overrides)
    return WorkspaceInvestigation(**defaults)  # type: ignore[arg-type]
