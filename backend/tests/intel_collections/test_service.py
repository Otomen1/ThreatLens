"""Tests for CollectionService (Phase 9.1).

Uses real ``WorkspaceService``/``CaseService`` (each over its own ``tmp_path``
subdirectory) as the linking collaborators rather than mocks — mirrors this
codebase's established preference for real, offline collaborators over
mocked ones wherever the real thing is this cheap to construct (see
``tests/cases/test_service.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from threatlens.cases import Case, CaseService, CreateCaseRequest
from threatlens.cases import LocalFileStorage as CaseLocalFileStorage
from threatlens.cases.exceptions import CaseNotFoundError
from threatlens.collections import (
    AddIndicatorRequest,
    CollectionNotFoundError,
    CollectionService,
    CollectionSource,
    CreateCollectionRequest,
    IndicatorType,
    LocalFileStorage,
    RemoveIndicatorRequest,
    UpdateCollectionRequest,
)
from threatlens.entities.types import EntityType
from threatlens.workspace import LocalFileStorage as WorkspaceLocalFileStorage
from threatlens.workspace import SaveInvestigationRequest, WorkspaceInvestigation, WorkspaceService
from threatlens.workspace.exceptions import InvestigationNotFoundError

NOW = datetime(2026, 7, 17, tzinfo=UTC)
LATER = datetime(2026, 7, 18, tzinfo=UTC)


def _seed_investigation(service: CollectionService, **overrides: object) -> WorkspaceInvestigation:
    defaults: dict[str, object] = {
        "title": "Linked investigation",
        "investigation_type": EntityType.IPV4,
    }
    defaults.update(overrides)
    return service._workspace.save(SaveInvestigationRequest(**defaults))  # type: ignore[arg-type]


def _seed_case(service: CollectionService, **overrides: object) -> Case:
    defaults: dict[str, object] = {"title": "Linked case"}
    defaults.update(overrides)
    return service._cases.create(CreateCaseRequest(**defaults))  # type: ignore[arg-type]


@pytest.fixture()
def service(tmp_path: Path) -> CollectionService:
    workspace = WorkspaceService(WorkspaceLocalFileStorage(tmp_path / "workspace"))
    cases = CaseService(CaseLocalFileStorage(tmp_path / "cases"), workspace)
    return CollectionService(LocalFileStorage(tmp_path / "collections"), workspace, cases)


class TestCreate:
    def test_assigns_fresh_id(self, service: CollectionService) -> None:
        a = service.create(CreateCollectionRequest(name="A"))
        b = service.create(CreateCollectionRequest(name="A"))
        assert a.id != b.id

    def test_sets_created_and_updated_at_to_now(self, service: CollectionService) -> None:
        record = service.create(CreateCollectionRequest(name="A"), now=NOW)
        assert record.created_at == NOW
        assert record.updated_at == NOW

    def test_defaults_to_manual_source(self, service: CollectionService) -> None:
        assert service.create(CreateCollectionRequest(name="A")).source == CollectionSource.MANUAL

    def test_accepts_explicit_source(self, service: CollectionService) -> None:
        record = service.create(
            CreateCollectionRequest(name="A", source=CollectionSource.WORKSPACE)
        )
        assert record.source == CollectionSource.WORKSPACE

    def test_starts_with_no_indicators_or_links(self, service: CollectionService) -> None:
        record = service.create(CreateCollectionRequest(name="A"))
        assert record.indicators == []
        assert record.linked_case_ids == []
        assert record.linked_workspace_ids == []


class TestGet:
    def test_returns_saved_record(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        assert service.get(created.id) == created

    def test_raises_for_missing_id(self, service: CollectionService) -> None:
        with pytest.raises(CollectionNotFoundError):
            service.get(uuid4())


class TestUpdate:
    def test_changes_only_given_fields(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A", category="campaign"))
        updated = service.update(created.id, UpdateCollectionRequest(name="B"), now=LATER)
        assert updated.name == "B"
        assert updated.category == "campaign"

    def test_bumps_updated_at(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"), now=NOW)
        updated = service.update(created.id, UpdateCollectionRequest(name="B"), now=LATER)
        assert updated.updated_at == LATER

    def test_null_tags_coerced_to_empty_list_not_none(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A", tags=["x"]))
        updated = service.update(created.id, UpdateCollectionRequest.model_validate({"tags": None}))
        assert updated.tags == []

    def test_null_metadata_coerced_to_empty_dict_not_none(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A", metadata={"k": "v"}))
        updated = service.update(
            created.id, UpdateCollectionRequest.model_validate({"metadata": None})
        )
        assert updated.metadata == {}

    def test_raises_for_missing_id(self, service: CollectionService) -> None:
        with pytest.raises(CollectionNotFoundError):
            service.update(uuid4(), UpdateCollectionRequest(name="x"))


class TestDelete:
    def test_removes_record(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        service.delete(created.id)
        with pytest.raises(CollectionNotFoundError):
            service.get(created.id)

    def test_raises_for_missing_id(self, service: CollectionService) -> None:
        with pytest.raises(CollectionNotFoundError):
            service.delete(uuid4())


class TestList:
    def test_empty_when_nothing_saved(self, service: CollectionService) -> None:
        assert service.list() == []

    def test_returns_every_collection_when_unfiltered(self, service: CollectionService) -> None:
        service.create(CreateCollectionRequest(name="A"))
        service.create(CreateCollectionRequest(name="B"))
        assert len(service.list()) == 2

    def test_sorted_most_recently_updated_first(self, service: CollectionService) -> None:
        a = service.create(CreateCollectionRequest(name="A"), now=NOW)
        b = service.create(CreateCollectionRequest(name="B"), now=LATER)
        assert [c.id for c in service.list()] == [b.id, a.id]

    def test_filter_by_name_substring_case_insensitive(self, service: CollectionService) -> None:
        service.create(CreateCollectionRequest(name="Silver Fox Campaign"))
        service.create(CreateCollectionRequest(name="APT29 Infrastructure"))
        assert [c.name for c in service.list(name="fox")] == ["Silver Fox Campaign"]

    def test_filter_by_category(self, service: CollectionService) -> None:
        service.create(CreateCollectionRequest(name="A", category="campaign"))
        service.create(CreateCollectionRequest(name="B", category="blocklist"))
        assert [c.name for c in service.list(category="blocklist")] == ["B"]

    def test_filter_by_indicator_type(self, service: CollectionService) -> None:
        a = service.create(CreateCollectionRequest(name="A"))
        service.create(CreateCollectionRequest(name="B"))
        service.add_indicator(a.id, AddIndicatorRequest(type=IndicatorType.CVE, value="CVE-2024-1"))
        assert [c.name for c in service.list(indicator_type=IndicatorType.CVE)] == ["A"]

    def test_filter_by_tag(self, service: CollectionService) -> None:
        service.create(CreateCollectionRequest(name="A", tags=["x"]))
        service.create(CreateCollectionRequest(name="B", tags=["y"]))
        assert [c.name for c in service.list(tag="y")] == ["B"]

    def test_filter_by_linked_case_id(self, service: CollectionService) -> None:
        case = _seed_case(service)
        a = service.create(CreateCollectionRequest(name="A"))
        service.create(CreateCollectionRequest(name="B"))
        service.link_case(a.id, case.id)
        assert [c.name for c in service.list(linked_case_id=case.id)] == ["A"]

    def test_filter_by_linked_workspace_id(self, service: CollectionService) -> None:
        investigation = _seed_investigation(service)
        a = service.create(CreateCollectionRequest(name="A"))
        service.create(CreateCollectionRequest(name="B"))
        service.link_workspace(a.id, investigation.id)
        assert [c.name for c in service.list(linked_workspace_id=investigation.id)] == ["A"]

    def test_filters_combine_with_and(self, service: CollectionService) -> None:
        service.create(CreateCollectionRequest(name="A", category="campaign", tags=["x"]))
        service.create(CreateCollectionRequest(name="B", category="campaign", tags=["y"]))
        result = service.list(category="campaign", tag="y")
        assert [c.name for c in result] == ["B"]


class TestAddIndicator:
    def test_adds_new_indicator(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com")
        )
        assert len(updated.indicators) == 1
        assert updated.indicators[0].value == "evil.com"

    def test_bumps_updated_at(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"), now=NOW)
        updated = service.add_indicator(
            created.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com"),
            now=LATER,
        )
        assert updated.updated_at == LATER

    def test_distinct_types_with_same_raw_value_do_not_collide(
        self, service: CollectionService
    ) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="123")
        )
        updated = service.add_indicator(
            updated.id, AddIndicatorRequest(type=IndicatorType.FILENAME, value="123")
        )
        assert len(updated.indicators) == 2

    def test_readd_with_same_identity_merges_not_duplicates(
        self, service: CollectionService
    ) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="Evil.COM")
        )
        updated = service.add_indicator(
            updated.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com")
        )
        assert len(updated.indicators) == 1

    def test_merge_unions_tags(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", tags=["c2", "shared"]),
        )
        updated = service.add_indicator(
            updated.id,
            AddIndicatorRequest(
                type=IndicatorType.DOMAIN, value="evil.com", tags=["stage2", "shared"]
            ),
        )
        assert updated.indicators[0].tags == ["c2", "shared", "stage2"]

    def test_merge_widens_first_seen_to_earliest(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", first_seen=LATER),
        )
        updated = service.add_indicator(
            updated.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", first_seen=NOW),
        )
        assert updated.indicators[0].first_seen == NOW

    def test_merge_widens_last_seen_to_latest(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", last_seen=NOW),
        )
        updated = service.add_indicator(
            updated.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", last_seen=LATER),
        )
        assert updated.indicators[0].last_seen == LATER

    def test_merge_keeps_existing_confidence_when_incoming_omits_it(
        self, service: CollectionService
    ) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", confidence=80),
        )
        updated = service.add_indicator(
            updated.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com")
        )
        assert updated.indicators[0].confidence == 80

    def test_merge_takes_incoming_confidence_when_provided(
        self, service: CollectionService
    ) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", confidence=50),
        )
        updated = service.add_indicator(
            updated.id,
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com", confidence=90),
        )
        assert updated.indicators[0].confidence == 90

    def test_merge_keeps_first_added_raw_value_spelling(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="Evil.COM")
        )
        updated = service.add_indicator(
            updated.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com")
        )
        assert updated.indicators[0].value == "Evil.COM"

    def test_raises_for_missing_collection(self, service: CollectionService) -> None:
        with pytest.raises(CollectionNotFoundError):
            service.add_indicator(
                uuid4(), AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com")
            )


class TestRemoveIndicator:
    def test_removes_matching_indicator(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com")
        )
        updated = service.remove_indicator(
            updated.id, RemoveIndicatorRequest(type=IndicatorType.DOMAIN, value="EVIL.COM")
        )
        assert updated.indicators == []

    def test_bumps_updated_at_on_real_removal(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"), now=NOW)
        updated = service.add_indicator(
            created.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com"), now=NOW
        )
        updated = service.remove_indicator(
            updated.id,
            RemoveIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com"),
            now=LATER,
        )
        assert updated.updated_at == LATER

    def test_idempotent_when_identity_not_present(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"), now=NOW)
        result = service.remove_indicator(
            created.id,
            RemoveIndicatorRequest(type=IndicatorType.DOMAIN, value="nope.com"),
            now=LATER,
        )
        assert result.updated_at == NOW  # unchanged, not bumped

    def test_only_removes_matching_type_not_other_types_with_same_value(
        self, service: CollectionService
    ) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.add_indicator(
            created.id, AddIndicatorRequest(type=IndicatorType.DOMAIN, value="123")
        )
        updated = service.add_indicator(
            updated.id, AddIndicatorRequest(type=IndicatorType.FILENAME, value="123")
        )
        updated = service.remove_indicator(
            updated.id, RemoveIndicatorRequest(type=IndicatorType.DOMAIN, value="123")
        )
        assert len(updated.indicators) == 1
        assert updated.indicators[0].type == IndicatorType.FILENAME

    def test_raises_for_missing_collection(self, service: CollectionService) -> None:
        with pytest.raises(CollectionNotFoundError):
            service.remove_indicator(
                uuid4(), RemoveIndicatorRequest(type=IndicatorType.DOMAIN, value="evil.com")
            )


class TestLinkWorkspace:
    def test_links_existing_investigation(self, service: CollectionService) -> None:
        investigation = _seed_investigation(service)
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.link_workspace(created.id, investigation.id)
        assert updated.linked_workspace_ids == [investigation.id]

    def test_idempotent_when_already_linked(self, service: CollectionService) -> None:
        investigation = _seed_investigation(service)
        created = service.create(CreateCollectionRequest(name="A"), now=NOW)
        service.link_workspace(created.id, investigation.id, now=NOW)
        result = service.link_workspace(created.id, investigation.id, now=LATER)
        assert result.updated_at == NOW  # unchanged, not bumped

    def test_raises_for_nonexistent_investigation(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        with pytest.raises(InvestigationNotFoundError):
            service.link_workspace(created.id, uuid4())

    def test_raises_for_missing_collection(self, service: CollectionService) -> None:
        investigation = _seed_investigation(service)
        with pytest.raises(CollectionNotFoundError):
            service.link_workspace(uuid4(), investigation.id)

    def test_one_investigation_can_be_linked_from_multiple_collections(
        self, service: CollectionService
    ) -> None:
        investigation = _seed_investigation(service)
        a = service.create(CreateCollectionRequest(name="A"))
        b = service.create(CreateCollectionRequest(name="B"))
        service.link_workspace(a.id, investigation.id)
        service.link_workspace(b.id, investigation.id)
        assert investigation.id in service.get(a.id).linked_workspace_ids
        assert investigation.id in service.get(b.id).linked_workspace_ids

    def test_never_mutates_the_linked_investigation(self, service: CollectionService) -> None:
        investigation = _seed_investigation(service)
        created = service.create(CreateCollectionRequest(name="A"))
        service.link_workspace(created.id, investigation.id)
        assert service._workspace.get(investigation.id) == investigation


class TestLinkCase:
    def test_links_existing_case(self, service: CollectionService) -> None:
        case = _seed_case(service)
        created = service.create(CreateCollectionRequest(name="A"))
        updated = service.link_case(created.id, case.id)
        assert updated.linked_case_ids == [case.id]

    def test_idempotent_when_already_linked(self, service: CollectionService) -> None:
        case = _seed_case(service)
        created = service.create(CreateCollectionRequest(name="A"), now=NOW)
        service.link_case(created.id, case.id, now=NOW)
        result = service.link_case(created.id, case.id, now=LATER)
        assert result.updated_at == NOW  # unchanged, not bumped

    def test_raises_for_nonexistent_case(self, service: CollectionService) -> None:
        created = service.create(CreateCollectionRequest(name="A"))
        with pytest.raises(CaseNotFoundError):
            service.link_case(created.id, uuid4())

    def test_raises_for_missing_collection(self, service: CollectionService) -> None:
        case = _seed_case(service)
        with pytest.raises(CollectionNotFoundError):
            service.link_case(uuid4(), case.id)

    def test_one_case_can_be_linked_from_multiple_collections(
        self, service: CollectionService
    ) -> None:
        case = _seed_case(service)
        a = service.create(CreateCollectionRequest(name="A"))
        b = service.create(CreateCollectionRequest(name="B"))
        service.link_case(a.id, case.id)
        service.link_case(b.id, case.id)
        assert case.id in service.get(a.id).linked_case_ids
        assert case.id in service.get(b.id).linked_case_ids

    def test_never_mutates_the_linked_case(self, service: CollectionService) -> None:
        case = _seed_case(service)
        created = service.create(CreateCollectionRequest(name="A"))
        service.link_case(created.id, case.id)
        assert service._cases.get(case.id) == case


def test_now_is_timezone_aware() -> None:
    assert NOW.tzinfo is UTC
    assert isinstance(NOW, datetime)
