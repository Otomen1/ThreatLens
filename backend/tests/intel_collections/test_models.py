"""Tests for Intelligence Collections models (Phase 9.1)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from threatlens.collections import (
    AddIndicatorRequest,
    Collection,
    CollectionSource,
    CreateCollectionRequest,
    Indicator,
    IndicatorType,
    LinkCaseRequest,
    LinkWorkspaceRequest,
    RemoveIndicatorRequest,
    UpdateCollectionRequest,
)

from .factories import NOW, collection, indicator


class TestIndicatorType:
    def test_closed_set(self) -> None:
        assert {t.value for t in IndicatorType} == {
            "ipv4",
            "ipv6",
            "domain",
            "hostname",
            "url",
            "email",
            "sha1",
            "sha256",
            "md5",
            "cve",
            "mitre_technique",
            "mitre_software",
            "mitre_group",
            "registry",
            "mutex",
            "filename",
            "process",
            "certificate",
        }


class TestCollectionSource:
    def test_closed_set(self) -> None:
        assert {s.value for s in CollectionSource} == {"manual", "workspace", "case"}


class TestIndicator:
    def test_defaults(self) -> None:
        ind = indicator()
        assert ind.first_seen is None
        assert ind.last_seen is None
        assert ind.confidence is None
        assert ind.tags == []
        assert ind.source is None
        assert ind.notes is None

    def test_blank_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            indicator(value="")

    def test_oversized_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            indicator(value="x" * 2049)

    def test_confidence_below_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            indicator(confidence=-1)

    def test_confidence_above_hundred_rejected(self) -> None:
        with pytest.raises(ValidationError):
            indicator(confidence=101)

    def test_confidence_bounds_accepted(self) -> None:
        assert indicator(confidence=0).confidence == 0
        assert indicator(confidence=100).confidence == 100

    def test_not_frozen_supports_model_copy(self) -> None:
        """Unlike CaseNote, an Indicator legitimately changes over its
        lifetime as new sightings merge in — see
        ``CollectionService.add_indicator``."""
        ind = indicator()
        updated = ind.model_copy(update={"confidence": 90})
        assert updated.confidence == 90
        assert ind.confidence is None  # original untouched

    def test_has_no_id_field(self) -> None:
        """Identity is (type, normalized_value), not a synthetic key."""
        assert "id" not in Indicator.model_fields


class TestCollection:
    def test_defaults(self) -> None:
        record = collection()
        assert record.description is None
        assert record.category is None
        assert record.tags == []
        assert record.source == CollectionSource.MANUAL
        assert record.linked_case_ids == []
        assert record.linked_workspace_ids == []
        assert record.metadata == {}
        assert record.indicators == []

    def test_id_is_uuid(self) -> None:
        assert isinstance(collection().id, UUID)

    def test_blank_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            collection(name="")

    def test_oversized_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            collection(name="x" * 201)

    def test_not_frozen_supports_model_copy(self) -> None:
        record = collection()
        updated = record.model_copy(update={"category": "campaign"})
        assert updated.category == "campaign"
        assert record.category is None  # original untouched

    def test_round_trips_through_json(self) -> None:
        record = collection(
            tags=["a", "b"],
            linked_workspace_ids=[uuid4()],
            linked_case_ids=[uuid4()],
            indicators=[indicator(tags=["c2"])],
            metadata={"k": "v"},
        )
        restored = Collection.model_validate_json(record.model_dump_json())
        assert restored == record


class TestCreateCollectionRequest:
    def test_requires_name(self) -> None:
        with pytest.raises(ValidationError):
            CreateCollectionRequest()  # type: ignore[call-arg]

    def test_defaults(self) -> None:
        req = CreateCollectionRequest(name="Collection")
        assert req.source == CollectionSource.MANUAL
        assert req.tags == []
        assert req.metadata == {}


class TestUpdateCollectionRequest:
    def test_all_fields_optional(self) -> None:
        req = UpdateCollectionRequest()
        assert req.model_dump(exclude_unset=True) == {}

    def test_exclude_unset_only_reports_provided_fields(self) -> None:
        req = UpdateCollectionRequest(category="campaign")
        assert req.model_dump(exclude_unset=True) == {"category": "campaign"}

    def test_explicit_null_is_reported_as_set(self) -> None:
        req = UpdateCollectionRequest.model_validate({"description": None})
        dumped = req.model_dump(exclude_unset=True)
        assert "description" in dumped
        assert dumped["description"] is None

    def test_blank_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UpdateCollectionRequest(name="")

    def test_has_no_source_field(self) -> None:
        """Source is provenance fixed at creation, not editable metadata."""
        assert "source" not in UpdateCollectionRequest.model_fields


class TestAddIndicatorRequest:
    def test_requires_type_and_value(self) -> None:
        with pytest.raises(ValidationError):
            AddIndicatorRequest()  # type: ignore[call-arg]

    def test_blank_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AddIndicatorRequest(type=IndicatorType.DOMAIN, value="")

    def test_accepts_optional_fields(self) -> None:
        req = AddIndicatorRequest(
            type=IndicatorType.IPV4,
            value="1.1.1.1",
            first_seen=NOW,
            last_seen=NOW,
            confidence=75,
            tags=["c2"],
            source="analyst",
            notes="seen in sandbox",
        )
        assert req.confidence == 75


class TestRemoveIndicatorRequest:
    def test_requires_type_and_value(self) -> None:
        with pytest.raises(ValidationError):
            RemoveIndicatorRequest()  # type: ignore[call-arg]

    def test_has_no_extra_fields(self) -> None:
        """Only identity fields — matching by (type, normalized_value), not
        by any of the indicator's other, non-identity attributes."""
        assert set(RemoveIndicatorRequest.model_fields) == {"type", "value"}


class TestLinkWorkspaceRequest:
    def test_requires_workspace_id(self) -> None:
        with pytest.raises(ValidationError):
            LinkWorkspaceRequest()  # type: ignore[call-arg]

    def test_accepts_uuid(self) -> None:
        wid = uuid4()
        assert LinkWorkspaceRequest(workspace_id=wid).workspace_id == wid


class TestLinkCaseRequest:
    def test_requires_case_id(self) -> None:
        with pytest.raises(ValidationError):
            LinkCaseRequest()  # type: ignore[call-arg]

    def test_accepts_uuid(self) -> None:
        cid = uuid4()
        assert LinkCaseRequest(case_id=cid).case_id == cid


def test_now_is_timezone_aware() -> None:
    assert NOW.tzinfo is UTC
    assert isinstance(NOW, datetime)
