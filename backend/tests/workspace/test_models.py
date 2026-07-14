"""Tests for Investigation Workspace models (Phase 8.0).

Covers the metadata envelope's own validation and defaults. Nested engine
outputs (InvestigationSummary, DetectionPackage, CorrelationSummary) are
reused verbatim from their own frozen packages and are not re-tested here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from threatlens.entities.types import EntityType
from threatlens.reasoning import Severity
from threatlens.workspace import (
    SaveInvestigationRequest,
    UpdateInvestigationRequest,
    WorkspaceInvestigation,
    WorkspaceStatus,
)

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def _record(**overrides: object) -> WorkspaceInvestigation:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "title": "Test investigation",
        "created_at": NOW,
        "updated_at": NOW,
        "investigation_type": EntityType.IPV4,
    }
    defaults.update(overrides)
    return WorkspaceInvestigation(**defaults)  # type: ignore[arg-type]


class TestWorkspaceStatus:
    def test_closed_set(self) -> None:
        assert {s.value for s in WorkspaceStatus} == {
            "open",
            "in_progress",
            "closed",
            "archived",
        }


class TestWorkspaceInvestigation:
    def test_defaults(self) -> None:
        record = _record()
        assert record.status == WorkspaceStatus.OPEN
        assert record.tags == []
        assert record.summary is None
        assert record.severity is None
        assert record.investigation_summary is None
        assert record.detection_package is None
        assert record.correlation_summary is None

    def test_id_is_uuid(self) -> None:
        record = _record()
        assert isinstance(record.id, UUID)

    def test_blank_title_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _record(title="")

    def test_oversized_title_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _record(title="x" * 201)

    def test_oversized_summary_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _record(summary="x" * 2001)

    def test_not_frozen_supports_model_copy(self) -> None:
        """Unlike every other model in this codebase, this one is mutated via
        model_copy over its lifetime — not frozen."""
        record = _record()
        updated = record.model_copy(update={"status": WorkspaceStatus.CLOSED})
        assert updated.status == WorkspaceStatus.CLOSED
        assert record.status == WorkspaceStatus.OPEN  # original untouched

    def test_round_trips_through_json(self) -> None:
        record = _record(tags=["a", "b"], severity=Severity.HIGH)
        restored = WorkspaceInvestigation.model_validate_json(record.model_dump_json())
        assert restored == record


class TestSaveInvestigationRequest:
    def test_requires_title_and_investigation_type(self) -> None:
        with pytest.raises(ValidationError):
            SaveInvestigationRequest()  # type: ignore[call-arg]

    def test_defaults(self) -> None:
        req = SaveInvestigationRequest(title="Case", investigation_type=EntityType.DOMAIN)
        assert req.status == WorkspaceStatus.OPEN
        assert req.tags == []
        assert req.summary is None
        assert req.severity is None


class TestUpdateInvestigationRequest:
    def test_all_fields_optional(self) -> None:
        req = UpdateInvestigationRequest()
        assert req.model_dump(exclude_unset=True) == {}

    def test_exclude_unset_only_reports_provided_fields(self) -> None:
        req = UpdateInvestigationRequest(status=WorkspaceStatus.CLOSED)
        dumped = req.model_dump(exclude_unset=True)
        assert dumped == {"status": WorkspaceStatus.CLOSED}

    def test_explicit_null_is_reported_as_set(self) -> None:
        """Explicitly clearing a field (sending null) must be distinguishable
        from never mentioning that field at all."""
        req = UpdateInvestigationRequest.model_validate({"summary": None})
        dumped = req.model_dump(exclude_unset=True)
        assert "summary" in dumped
        assert dumped["summary"] is None

    def test_blank_title_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UpdateInvestigationRequest(title="")
