"""Tests for CaseService (Phase 9.0).

Uses a real ``WorkspaceService``/``LocalFileStorage`` pair (over a separate
``tmp_path`` subdirectory) as the linking collaborator rather than a mock —
mirrors this codebase's established preference for real, offline collaborators
over mocked ones wherever the real thing is this cheap to construct.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from threatlens.cases import (
    AddNoteRequest,
    CaseNotFoundError,
    CasePriority,
    CaseService,
    CaseStatus,
    CreateCaseRequest,
    InvalidStatusTransitionError,
    LocalFileStorage,
    UpdateCaseRequest,
)
from threatlens.entities.types import EntityType
from threatlens.workspace import LocalFileStorage as WorkspaceLocalFileStorage
from threatlens.workspace import SaveInvestigationRequest, WorkspaceInvestigation, WorkspaceService
from threatlens.workspace.exceptions import InvestigationNotFoundError

NOW = datetime(2026, 7, 17, tzinfo=UTC)
LATER = datetime(2026, 7, 18, tzinfo=UTC)


def _seed_investigation(service: CaseService, **overrides: object) -> WorkspaceInvestigation:
    """Save a real Workspace investigation through the public
    ``WorkspaceService`` API (never the storage layer directly) so linking
    tests reference a genuinely existing, service-assigned id."""
    defaults: dict[str, object] = {
        "title": "Linked investigation",
        "investigation_type": EntityType.IPV4,
    }
    defaults.update(overrides)
    return service._workspace.save(SaveInvestigationRequest(**defaults))  # type: ignore[arg-type]


@pytest.fixture()
def service(tmp_path: Path) -> CaseService:
    workspace = WorkspaceService(WorkspaceLocalFileStorage(tmp_path / "workspace"))
    return CaseService(LocalFileStorage(tmp_path / "cases"), workspace)


class TestCreate:
    def test_assigns_fresh_id(self, service: CaseService) -> None:
        a = service.create(CreateCaseRequest(title="A"))
        b = service.create(CreateCaseRequest(title="A"))
        assert a.id != b.id

    def test_sets_created_and_updated_to_now(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        assert created.created_at == NOW
        assert created.updated_at == NOW

    def test_defaults_now_when_not_given(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"))
        assert created.created_at.tzinfo is not None

    def test_persists_via_storage(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        assert service.get(created.id) == created

    def test_saving_identical_content_twice_creates_two_records(self, service: CaseService) -> None:
        req = CreateCaseRequest(title="Duplicate")
        a = service.create(req, now=NOW)
        b = service.create(req, now=NOW)
        assert a.id != b.id
        assert len(service.list()) == 2


class TestGet:
    def test_raises_not_found_for_missing_id(self, service: CaseService) -> None:
        with pytest.raises(CaseNotFoundError):
            service.get(uuid4())


class TestUpdate:
    def test_raises_not_found_for_missing_id(self, service: CaseService) -> None:
        with pytest.raises(CaseNotFoundError):
            service.update(uuid4(), UpdateCaseRequest(title="x"))

    def test_changes_only_provided_fields(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A", owner="alice"), now=NOW)
        updated = service.update(created.id, UpdateCaseRequest(title="B"), now=LATER)
        assert updated.title == "B"
        assert updated.owner == "alice"

    def test_bumps_updated_at_but_not_created_at(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        updated = service.update(created.id, UpdateCaseRequest(title="B"), now=LATER)
        assert updated.created_at == NOW
        assert updated.updated_at == LATER

    def test_explicit_null_clears_description(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A", description="d"), now=NOW)
        updated = service.update(
            created.id, UpdateCaseRequest.model_validate({"description": None}), now=LATER
        )
        assert updated.description is None

    def test_explicit_null_clears_tags_to_empty_list(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A", tags=["x"]), now=NOW)
        updated = service.update(
            created.id, UpdateCaseRequest.model_validate({"tags": None}), now=LATER
        )
        assert updated.tags == []

    def test_explicit_null_clears_metadata_to_empty_dict(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A", metadata={"k": "v"}), now=NOW)
        updated = service.update(
            created.id, UpdateCaseRequest.model_validate({"metadata": None}), now=LATER
        )
        assert updated.metadata == {}

    def test_persists_the_update(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        service.update(created.id, UpdateCaseRequest(title="B"), now=LATER)
        assert service.get(created.id).title == "B"

    @pytest.mark.parametrize(
        "current,requested",
        [
            (CaseStatus.OPEN, CaseStatus.IN_PROGRESS),
            (CaseStatus.OPEN, CaseStatus.CLOSED),
            (CaseStatus.IN_PROGRESS, CaseStatus.OPEN),
            (CaseStatus.IN_PROGRESS, CaseStatus.RESOLVED),
            (CaseStatus.IN_PROGRESS, CaseStatus.CLOSED),
            (CaseStatus.RESOLVED, CaseStatus.IN_PROGRESS),
            (CaseStatus.RESOLVED, CaseStatus.CLOSED),
            (CaseStatus.CLOSED, CaseStatus.OPEN),
        ],
    )
    def test_allowed_transition_succeeds(
        self, service: CaseService, current: CaseStatus, requested: CaseStatus
    ) -> None:
        created = service.create(CreateCaseRequest(title="A", status=current), now=NOW)
        updated = service.update(created.id, UpdateCaseRequest(status=requested), now=LATER)
        assert updated.status == requested

    @pytest.mark.parametrize(
        "current,requested",
        [
            (CaseStatus.OPEN, CaseStatus.RESOLVED),
            (CaseStatus.RESOLVED, CaseStatus.OPEN),
            (CaseStatus.CLOSED, CaseStatus.IN_PROGRESS),
            (CaseStatus.CLOSED, CaseStatus.RESOLVED),
        ],
    )
    def test_disallowed_transition_raises_and_leaves_case_unchanged(
        self, service: CaseService, current: CaseStatus, requested: CaseStatus
    ) -> None:
        created = service.create(CreateCaseRequest(title="A", status=current), now=NOW)
        with pytest.raises(InvalidStatusTransitionError):
            service.update(created.id, UpdateCaseRequest(status=requested), now=LATER)
        assert service.get(created.id).status == current
        assert service.get(created.id).updated_at == NOW

    @pytest.mark.parametrize("status", list(CaseStatus))
    def test_same_status_is_always_a_no_op_transition(
        self, service: CaseService, status: CaseStatus
    ) -> None:
        created = service.create(CreateCaseRequest(title="A", status=status), now=NOW)
        updated = service.update(created.id, UpdateCaseRequest(status=status), now=LATER)
        assert updated.status == status
        assert updated.updated_at == LATER  # still a real update — updated_at moves


class TestPriority:
    @pytest.mark.parametrize("priority", list(CasePriority))
    def test_create_accepts_every_priority(
        self, service: CaseService, priority: CasePriority
    ) -> None:
        created = service.create(CreateCaseRequest(title="A", priority=priority))
        assert created.priority == priority

    def test_update_changes_priority(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A", priority=CasePriority.LOW))
        updated = service.update(created.id, UpdateCaseRequest(priority=CasePriority.CRITICAL))
        assert updated.priority == CasePriority.CRITICAL


class TestDelete:
    def test_raises_not_found_for_missing_id(self, service: CaseService) -> None:
        with pytest.raises(CaseNotFoundError):
            service.delete(uuid4())

    def test_removes_record(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"))
        service.delete(created.id)
        with pytest.raises(CaseNotFoundError):
            service.get(created.id)


class TestList:
    def test_empty(self, service: CaseService) -> None:
        assert service.list() == []

    def test_returns_every_record_with_no_filters(self, service: CaseService) -> None:
        service.create(CreateCaseRequest(title="A"))
        service.create(CreateCaseRequest(title="B"))
        assert len(service.list()) == 2

    def test_most_recently_updated_first(self, service: CaseService) -> None:
        a = service.create(CreateCaseRequest(title="A"), now=NOW)
        b = service.create(CreateCaseRequest(title="B"), now=LATER)
        assert [c.id for c in service.list()] == [b.id, a.id]

    def test_filter_by_status(self, service: CaseService) -> None:
        service.create(CreateCaseRequest(title="A", status=CaseStatus.OPEN))
        service.create(CreateCaseRequest(title="B", status=CaseStatus.CLOSED))
        results = service.list(status=CaseStatus.CLOSED)
        assert [c.title for c in results] == ["B"]

    def test_filter_by_priority(self, service: CaseService) -> None:
        service.create(CreateCaseRequest(title="A", priority=CasePriority.LOW))
        service.create(CreateCaseRequest(title="B", priority=CasePriority.CRITICAL))
        results = service.list(priority=CasePriority.CRITICAL)
        assert [c.title for c in results] == ["B"]

    def test_filter_by_tag(self, service: CaseService) -> None:
        service.create(CreateCaseRequest(title="A", tags=["phishing"]))
        service.create(CreateCaseRequest(title="B", tags=["ransomware"]))
        results = service.list(tag="ransomware")
        assert [c.title for c in results] == ["B"]

    def test_filter_by_owner(self, service: CaseService) -> None:
        service.create(CreateCaseRequest(title="A", owner="alice"))
        service.create(CreateCaseRequest(title="B", owner="bob"))
        results = service.list(owner="bob")
        assert [c.title for c in results] == ["B"]

    def test_filter_by_title_is_case_insensitive_substring(self, service: CaseService) -> None:
        service.create(CreateCaseRequest(title="Suspicious Login Activity"))
        service.create(CreateCaseRequest(title="Malware Outbreak"))
        results = service.list(title="LOGIN")
        assert [c.title for c in results] == ["Suspicious Login Activity"]

    def test_filters_combine_with_and(self, service: CaseService) -> None:
        service.create(
            CreateCaseRequest(title="A", status=CaseStatus.OPEN, priority=CasePriority.HIGH)
        )
        service.create(
            CreateCaseRequest(title="B", status=CaseStatus.OPEN, priority=CasePriority.LOW)
        )
        results = service.list(status=CaseStatus.OPEN, priority=CasePriority.HIGH)
        assert [c.title for c in results] == ["A"]

    def test_no_matches_returns_empty_list(self, service: CaseService) -> None:
        service.create(CreateCaseRequest(title="A"))
        assert service.list(title="nonexistent") == []


class TestLinkWorkspace:
    def test_links_existing_investigation(self, service: CaseService) -> None:
        inv = _seed_investigation(service)
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        updated = service.link_workspace(created.id, inv.id, now=LATER)
        assert updated.linked_workspace_ids == [inv.id]

    def test_raises_investigation_not_found_for_nonexistent_workspace_id(
        self, service: CaseService
    ) -> None:
        created = service.create(CreateCaseRequest(title="A"))
        with pytest.raises(InvestigationNotFoundError):
            service.link_workspace(created.id, uuid4())

    def test_raises_case_not_found_for_missing_case(self, service: CaseService) -> None:
        inv = _seed_investigation(service)
        with pytest.raises(CaseNotFoundError):
            service.link_workspace(uuid4(), inv.id)

    def test_linking_twice_is_idempotent(self, service: CaseService) -> None:
        inv = _seed_investigation(service)
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        service.link_workspace(created.id, inv.id, now=LATER)
        twice = service.link_workspace(created.id, inv.id, now=LATER)
        assert twice.linked_workspace_ids == [inv.id]

    def test_idempotent_link_does_not_bump_updated_at(self, service: CaseService) -> None:
        inv = _seed_investigation(service)
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        first = service.link_workspace(created.id, inv.id, now=LATER)
        second = service.link_workspace(created.id, inv.id, now=LATER)
        assert first.updated_at == second.updated_at

    def test_can_link_multiple_distinct_investigations(self, service: CaseService) -> None:
        inv1 = _seed_investigation(service, title="First")
        inv2 = _seed_investigation(service, title="Second")
        created = service.create(CreateCaseRequest(title="A"))
        service.link_workspace(created.id, inv1.id)
        updated = service.link_workspace(created.id, inv2.id)
        assert set(updated.linked_workspace_ids) == {inv1.id, inv2.id}

    def test_one_investigation_can_be_linked_from_multiple_cases(
        self, service: CaseService
    ) -> None:
        """The relationship is many-to-many — never enforced one-to-one."""
        inv = _seed_investigation(service)
        case_a = service.create(CreateCaseRequest(title="A"))
        case_b = service.create(CreateCaseRequest(title="B"))
        updated_a = service.link_workspace(case_a.id, inv.id)
        updated_b = service.link_workspace(case_b.id, inv.id)
        assert updated_a.linked_workspace_ids == [inv.id]
        assert updated_b.linked_workspace_ids == [inv.id]

    def test_never_mutates_the_linked_investigation(self, service: CaseService) -> None:
        inv = _seed_investigation(service)
        created = service.create(CreateCaseRequest(title="A"))
        service.link_workspace(created.id, inv.id)
        assert service._workspace.get(inv.id) == inv


class TestUnlinkWorkspace:
    def test_removes_the_link(self, service: CaseService) -> None:
        inv = _seed_investigation(service)
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        service.link_workspace(created.id, inv.id, now=NOW)
        updated = service.unlink_workspace(created.id, inv.id, now=LATER)
        assert updated.linked_workspace_ids == []

    def test_unlinking_non_linked_id_is_idempotent_no_op(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        updated = service.unlink_workspace(created.id, uuid4(), now=LATER)
        assert updated.linked_workspace_ids == []
        assert updated.updated_at == NOW  # unchanged — no-op

    def test_raises_case_not_found_for_missing_case(self, service: CaseService) -> None:
        with pytest.raises(CaseNotFoundError):
            service.unlink_workspace(uuid4(), uuid4())

    def test_never_touches_the_investigation_itself(self, service: CaseService) -> None:
        inv = _seed_investigation(service)
        created = service.create(CreateCaseRequest(title="A"))
        service.link_workspace(created.id, inv.id)
        service.unlink_workspace(created.id, inv.id)
        assert service._workspace.get(inv.id) == inv


class TestAddNote:
    def test_appends_a_note(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"))
        updated = service.add_note(
            created.id, AddNoteRequest(author="analyst", content="First note"), now=NOW
        )
        assert len(updated.notes) == 1
        assert updated.notes[0].author == "analyst"
        assert updated.notes[0].content == "First note"
        assert updated.notes[0].timestamp == NOW

    def test_appends_in_order_oldest_first(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"))
        service.add_note(created.id, AddNoteRequest(author="a", content="one"), now=NOW)
        updated = service.add_note(created.id, AddNoteRequest(author="b", content="two"), now=LATER)
        assert [n.content for n in updated.notes] == ["one", "two"]

    def test_bumps_updated_at(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"), now=NOW)
        updated = service.add_note(
            created.id, AddNoteRequest(author="a", content="note"), now=LATER
        )
        assert updated.updated_at == LATER
        assert updated.created_at == NOW

    def test_raises_not_found_for_missing_case(self, service: CaseService) -> None:
        with pytest.raises(CaseNotFoundError):
            service.add_note(uuid4(), AddNoteRequest(author="a", content="note"))

    def test_persists_the_note(self, service: CaseService) -> None:
        created = service.create(CreateCaseRequest(title="A"))
        service.add_note(created.id, AddNoteRequest(author="a", content="note"))
        assert len(service.get(created.id).notes) == 1
