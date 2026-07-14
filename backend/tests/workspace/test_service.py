"""Tests for WorkspaceService (Phase 8.0): CRUD, filtering, and metadata updates.

All offline, using LocalFileStorage over pytest's ``tmp_path``. No network, no
AI, no reasoning/correlation logic exercised — the service is pure plumbing
over already-computed inputs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from threatlens.entities.types import EntityType
from threatlens.reasoning import Severity
from threatlens.workspace import (
    InvestigationNotFoundError,
    LocalFileStorage,
    SaveInvestigationRequest,
    UpdateInvestigationRequest,
    WorkspaceService,
    WorkspaceStatus,
)

NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=UTC)
LATER = datetime(2026, 7, 14, 13, 0, 0, tzinfo=UTC)


@pytest.fixture()
def service(tmp_path: Path) -> WorkspaceService:
    return WorkspaceService(LocalFileStorage(tmp_path))


def _save(
    service: WorkspaceService,
    *,
    title: str = "Case",
    investigation_type: EntityType = EntityType.IPV4,
    now: datetime = NOW,
    **kwargs: object,
) -> object:
    request = SaveInvestigationRequest(
        title=title, investigation_type=investigation_type, **kwargs
    )  # type: ignore[arg-type]
    return service.save(request, now=now)


# --------------------------------------------------------------------------- #
# save / get / delete
# --------------------------------------------------------------------------- #


class TestSave:
    def test_assigns_fresh_id(self, service: WorkspaceService) -> None:
        a = _save(service)
        b = _save(service)
        assert a.id != b.id  # type: ignore[attr-defined]

    def test_sets_created_and_updated_to_now(self, service: WorkspaceService) -> None:
        record = _save(service, now=NOW)
        assert record.created_at == NOW  # type: ignore[attr-defined]
        assert record.updated_at == NOW  # type: ignore[attr-defined]

    def test_defaults_now_when_not_given(self, service: WorkspaceService) -> None:
        request = SaveInvestigationRequest(title="Case", investigation_type=EntityType.IPV4)
        before = datetime.now(UTC)
        record = service.save(request)
        after = datetime.now(UTC)
        assert before <= record.created_at <= after

    def test_persists_via_storage(self, service: WorkspaceService) -> None:
        record = _save(service)
        assert service.get(record.id) == record  # type: ignore[attr-defined]

    def test_saving_identical_content_twice_creates_two_records(
        self, service: WorkspaceService
    ) -> None:
        a = _save(service, title="Same title")
        b = _save(service, title="Same title")
        assert a.id != b.id  # type: ignore[attr-defined]
        assert len(service.list()) == 2


class TestGet:
    def test_raises_not_found_for_missing_id(self, service: WorkspaceService) -> None:
        with pytest.raises(InvestigationNotFoundError):
            service.get(uuid4())


class TestDelete:
    def test_removes_record(self, service: WorkspaceService) -> None:
        record = _save(service)
        service.delete(record.id)  # type: ignore[attr-defined]
        with pytest.raises(InvestigationNotFoundError):
            service.get(record.id)  # type: ignore[attr-defined]

    def test_raises_not_found_for_missing_id(self, service: WorkspaceService) -> None:
        with pytest.raises(InvestigationNotFoundError):
            service.delete(uuid4())


# --------------------------------------------------------------------------- #
# update — partial-update semantics
# --------------------------------------------------------------------------- #


class TestUpdate:
    def test_raises_not_found_for_missing_id(self, service: WorkspaceService) -> None:
        with pytest.raises(InvestigationNotFoundError):
            service.update(uuid4(), UpdateInvestigationRequest(title="x"))

    def test_changes_only_provided_fields(self, service: WorkspaceService) -> None:
        record = _save(service, title="Original", tags=["a"])
        updated = service.update(
            record.id,  # type: ignore[attr-defined]
            UpdateInvestigationRequest(status=WorkspaceStatus.CLOSED),
            now=LATER,
        )
        assert updated.status == WorkspaceStatus.CLOSED
        assert updated.title == "Original"  # untouched
        assert updated.tags == ["a"]  # untouched

    def test_bumps_updated_at_but_not_created_at(self, service: WorkspaceService) -> None:
        record = _save(service, now=NOW)
        updated = service.update(
            record.id,  # type: ignore[attr-defined]
            UpdateInvestigationRequest(title="Renamed"),
            now=LATER,
        )
        assert updated.created_at == NOW
        assert updated.updated_at == LATER

    def test_explicit_null_clears_a_field(self, service: WorkspaceService) -> None:
        record = _save(service, summary="Initial note")
        patch = UpdateInvestigationRequest.model_validate({"summary": None})
        updated = service.update(record.id, patch)  # type: ignore[attr-defined]
        assert updated.summary is None

    def test_persists_the_update(self, service: WorkspaceService) -> None:
        record = _save(service)
        service.update(
            record.id, UpdateInvestigationRequest(status=WorkspaceStatus.ARCHIVED)  # type: ignore[attr-defined]
        )
        assert service.get(record.id).status == WorkspaceStatus.ARCHIVED  # type: ignore[attr-defined]

    def test_can_reattach_a_severity(self, service: WorkspaceService) -> None:
        record = _save(service)
        updated = service.update(
            record.id, UpdateInvestigationRequest(severity=Severity.CRITICAL)  # type: ignore[attr-defined]
        )
        assert updated.severity == Severity.CRITICAL


# --------------------------------------------------------------------------- #
# list — filtering and sorting
# --------------------------------------------------------------------------- #


class TestList:
    def test_empty_workspace(self, service: WorkspaceService) -> None:
        assert service.list() == []

    def test_returns_every_record_with_no_filters(self, service: WorkspaceService) -> None:
        _save(service, title="A")
        _save(service, title="B")
        assert len(service.list()) == 2

    def test_most_recently_updated_first(self, service: WorkspaceService) -> None:
        older = _save(service, title="Older", now=NOW)
        newer = _save(service, title="Newer", now=LATER)
        listed = service.list()
        assert [r.id for r in listed] == [newer.id, older.id]  # type: ignore[attr-defined]

    def test_filter_by_status(self, service: WorkspaceService) -> None:
        open_case = _save(service, title="Open one")
        closed_case = _save(service, title="Closed one", status=WorkspaceStatus.CLOSED)
        result = service.list(status=WorkspaceStatus.CLOSED)
        assert [r.id for r in result] == [closed_case.id]  # type: ignore[attr-defined]
        assert open_case.id not in [r.id for r in result]  # type: ignore[attr-defined]

    def test_filter_by_severity(self, service: WorkspaceService) -> None:
        _save(service, title="Low", severity=Severity.LOW)
        high = _save(service, title="High", severity=Severity.HIGH)
        result = service.list(severity=Severity.HIGH)
        assert [r.id for r in result] == [high.id]  # type: ignore[attr-defined]

    def test_filter_by_investigation_type(self, service: WorkspaceService) -> None:
        _save(service, title="IP case", investigation_type=EntityType.IPV4)
        domain_case = _save(service, title="Domain case", investigation_type=EntityType.DOMAIN)
        result = service.list(investigation_type=EntityType.DOMAIN)
        assert [r.id for r in result] == [domain_case.id]  # type: ignore[attr-defined]

    def test_filter_by_tag(self, service: WorkspaceService) -> None:
        _save(service, title="No tags")
        tagged = _save(service, title="Tagged", tags=["urgent", "ioc"])
        result = service.list(tag="urgent")
        assert [r.id for r in result] == [tagged.id]  # type: ignore[attr-defined]

    def test_search_matches_title_case_insensitively(self, service: WorkspaceService) -> None:
        match = _save(service, title="Suspicious Login")
        _save(service, title="Something else")
        result = service.list(query="suspicious")
        assert [r.id for r in result] == [match.id]  # type: ignore[attr-defined]

    def test_search_matches_summary(self, service: WorkspaceService) -> None:
        match = _save(service, title="Case A", summary="Contains a rare keyword")
        _save(service, title="Case B", summary="Nothing relevant")
        result = service.list(query="rare keyword")
        assert [r.id for r in result] == [match.id]  # type: ignore[attr-defined]

    def test_search_matches_tags(self, service: WorkspaceService) -> None:
        match = _save(service, title="Case A", tags=["zeroday"])
        _save(service, title="Case B", tags=["routine"])
        result = service.list(query="zeroday")
        assert [r.id for r in result] == [match.id]  # type: ignore[attr-defined]

    def test_filters_combine_with_and(self, service: WorkspaceService) -> None:
        target = _save(
            service,
            title="Target",
            status=WorkspaceStatus.CLOSED,
            severity=Severity.HIGH,
            tags=["match"],
        )
        _save(service, title="Wrong status", severity=Severity.HIGH, tags=["match"])
        _save(service, title="Wrong severity", status=WorkspaceStatus.CLOSED, tags=["match"])
        result = service.list(status=WorkspaceStatus.CLOSED, severity=Severity.HIGH, tag="match")
        assert [r.id for r in result] == [target.id]  # type: ignore[attr-defined]

    def test_no_matches_returns_empty_list(self, service: WorkspaceService) -> None:
        _save(service, title="Case")
        assert service.list(query="no such needle anywhere") == []
