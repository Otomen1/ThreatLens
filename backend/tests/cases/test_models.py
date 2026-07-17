"""Tests for Case Management models (Phase 9.0)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from threatlens.cases import (
    AddNoteRequest,
    Case,
    CaseNote,
    CasePriority,
    CaseStatus,
    CreateCaseRequest,
    LinkWorkspaceRequest,
    UpdateCaseRequest,
)

from .factories import NOW, case


class TestCaseStatus:
    def test_closed_set(self) -> None:
        assert {s.value for s in CaseStatus} == {"open", "in_progress", "resolved", "closed"}


class TestCasePriority:
    def test_closed_set(self) -> None:
        assert {p.value for p in CasePriority} == {"low", "medium", "high", "critical"}


class TestCase:
    def test_defaults(self) -> None:
        record = case()
        assert record.status == CaseStatus.OPEN
        assert record.priority == CasePriority.MEDIUM
        assert record.description is None
        assert record.owner is None
        assert record.tags == []
        assert record.linked_workspace_ids == []
        assert record.notes == []
        assert record.metadata == {}

    def test_id_is_uuid(self) -> None:
        assert isinstance(case().id, UUID)

    def test_blank_title_rejected(self) -> None:
        with pytest.raises(ValidationError):
            case(title="")

    def test_oversized_title_rejected(self) -> None:
        with pytest.raises(ValidationError):
            case(title="x" * 201)

    def test_oversized_description_rejected(self) -> None:
        with pytest.raises(ValidationError):
            case(description="x" * 2001)

    def test_not_frozen_supports_model_copy(self) -> None:
        """Mirrors WorkspaceInvestigation: an operational record mutated over
        its lifetime, not a frozen projection."""
        record = case()
        updated = record.model_copy(update={"status": CaseStatus.CLOSED})
        assert updated.status == CaseStatus.CLOSED
        assert record.status == CaseStatus.OPEN  # original untouched

    def test_round_trips_through_json(self) -> None:
        record = case(
            tags=["a", "b"],
            linked_workspace_ids=[uuid4()],
            notes=[CaseNote(author="analyst", timestamp=NOW, content="note")],
            metadata={"k": "v"},
        )
        restored = Case.model_validate_json(record.model_dump_json())
        assert restored == record


class TestCaseNote:
    def test_frozen(self) -> None:
        note = CaseNote(author="analyst", timestamp=NOW, content="hello")
        with pytest.raises(ValidationError):
            note.author = "someone-else"  # type: ignore[misc]

    def test_blank_author_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CaseNote(author="", timestamp=NOW, content="hello")

    def test_blank_content_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CaseNote(author="analyst", timestamp=NOW, content="")

    def test_oversized_content_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CaseNote(author="analyst", timestamp=NOW, content="x" * 4001)


class TestCreateCaseRequest:
    def test_requires_title(self) -> None:
        with pytest.raises(ValidationError):
            CreateCaseRequest()  # type: ignore[call-arg]

    def test_defaults(self) -> None:
        req = CreateCaseRequest(title="Case")
        assert req.status == CaseStatus.OPEN
        assert req.priority == CasePriority.MEDIUM
        assert req.tags == []
        assert req.metadata == {}


class TestUpdateCaseRequest:
    def test_all_fields_optional(self) -> None:
        req = UpdateCaseRequest()
        assert req.model_dump(exclude_unset=True) == {}

    def test_exclude_unset_only_reports_provided_fields(self) -> None:
        req = UpdateCaseRequest(status=CaseStatus.CLOSED)
        assert req.model_dump(exclude_unset=True) == {"status": CaseStatus.CLOSED}

    def test_explicit_null_is_reported_as_set(self) -> None:
        """Explicitly clearing a field (sending null) must be distinguishable
        from never mentioning that field at all."""
        req = UpdateCaseRequest.model_validate({"description": None})
        dumped = req.model_dump(exclude_unset=True)
        assert "description" in dumped
        assert dumped["description"] is None

    def test_blank_title_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UpdateCaseRequest(title="")


class TestLinkWorkspaceRequest:
    def test_requires_workspace_id(self) -> None:
        with pytest.raises(ValidationError):
            LinkWorkspaceRequest()  # type: ignore[call-arg]

    def test_accepts_uuid(self) -> None:
        wid = uuid4()
        assert LinkWorkspaceRequest(workspace_id=wid).workspace_id == wid


class TestAddNoteRequest:
    def test_requires_author_and_content(self) -> None:
        with pytest.raises(ValidationError):
            AddNoteRequest()  # type: ignore[call-arg]

    def test_blank_content_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AddNoteRequest(author="analyst", content="")


def test_now_is_timezone_aware() -> None:
    assert NOW.tzinfo is UTC
    assert isinstance(NOW, datetime)
