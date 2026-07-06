"""Model serialization and classmethod tests for the Identity Intelligence Framework."""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.entities.types import EntityType
from threatlens.identity.models import (
    IdentityAsset,
    IdentityAuthType,
    IdentityCapability,
    IdentityEvidence,
    IdentityFinding,
    IdentityMetadata,
    IdentityProviderMetadata,
    IdentityReference,
    IdentityStatistics,
    IdentityStatus,
    IdentitySummary,
)


class TestIdentityProviderMetadata:
    def test_requires_auth_true_for_api_key(self) -> None:
        meta = IdentityProviderMetadata(
            name="hibp",
            display_name="Have I Been Pwned",
            supported_entity_types=frozenset({EntityType.EMAIL}),
        )
        assert meta.requires_auth is True

    def test_requires_auth_false_for_none(self) -> None:
        meta = IdentityProviderMetadata(
            name="free",
            display_name="Free",
            supported_entity_types=frozenset({EntityType.EMAIL}),
            auth_type=IdentityAuthType.NONE,
        )
        assert meta.requires_auth is False

    def test_default_priority_is_100(self) -> None:
        meta = IdentityProviderMetadata(
            name="p", display_name="P", supported_entity_types=frozenset({EntityType.EMAIL})
        )
        assert meta.priority == 100
        assert meta.enabled is True


class TestIdentityFinding:
    def test_not_found_has_no_error(self) -> None:
        finding = IdentityFinding.not_found(
            provider="hibp", entity_type=EntityType.EMAIL, entity_value="a@b.com"
        )
        assert finding.status == IdentityStatus.NOT_FOUND
        assert finding.error is None
        assert finding.is_ok is False
        assert finding.has_findings is False

    def test_unsupported(self) -> None:
        finding = IdentityFinding.unsupported(
            provider="hibp", entity_type=EntityType.IPV4, entity_value="8.8.8.8"
        )
        assert finding.status == IdentityStatus.UNSUPPORTED

    def test_failure_carries_error(self) -> None:
        finding = IdentityFinding.failure(
            provider="hibp",
            entity_type=EntityType.EMAIL,
            entity_value="a@b.com",
            message="boom",
            detail="stack trace redacted",
        )
        assert finding.is_error is True
        assert finding.error is not None
        assert finding.error.message == "boom"

    def test_ok_finding_with_data_has_findings(self) -> None:
        finding = IdentityFinding(
            provider="hibp",
            entity_type=EntityType.EMAIL,
            entity_value="a@b.com",
            status=IdentityStatus.OK,
            category=IdentityCapability.BREACHES,
            summary="2 breaches",
            evidence=[IdentityEvidence(type="breach", summary="Collection #1 (2019)")],
            assets=[IdentityAsset(asset_type="breached_account", value="a@b.com")],
        )
        assert finding.has_findings is True
        assert finding.is_ok is True

    def test_round_trip_serialization(self) -> None:
        finding = IdentityFinding(
            provider="hibp",
            provider_display_name="Have I Been Pwned",
            entity_type=EntityType.EMAIL,
            entity_value="a@b.com",
            category=IdentityCapability.BREACHES,
            summary="test",
            references=[IdentityReference(title="t", url="https://x")],
        )
        payload = finding.model_dump_json()
        restored = IdentityFinding.model_validate_json(payload)
        assert restored == finding


class TestIdentitySummary:
    def test_round_trip_serialization(self) -> None:
        summary = IdentitySummary(
            entity_type=EntityType.EMAIL,
            entity_value="a@b.com",
            statistics=IdentityStatistics(),
            metadata=IdentityMetadata(
                entity_type=EntityType.EMAIL,
                entity_value="a@b.com",
                generated_at=datetime.now(UTC),
                framework_version="0.1.0",
            ),
        )
        restored = IdentitySummary.model_validate_json(summary.model_dump_json())
        assert restored == summary

    def test_empty_summary_has_no_findings(self) -> None:
        summary = IdentitySummary(
            entity_type=EntityType.EMAIL,
            entity_value="a@b.com",
            statistics=IdentityStatistics(),
            metadata=IdentityMetadata(
                entity_type=EntityType.EMAIL,
                entity_value="a@b.com",
                generated_at=datetime.now(UTC),
                framework_version="0.1.0",
            ),
        )
        assert summary.has_findings is False
        assert summary.findings == []


class TestVocabularies:
    def test_capability_values_are_stable_strings(self) -> None:
        # A closed vocabulary: value strings are part of the API/serialization
        # contract, so pin them against accidental rename.
        assert IdentityCapability.BREACHES.value == "breaches"
        assert IdentityCapability.DIRECTORY_PROFILE.value == "directory_profile"
        assert IdentityCapability.MFA_STATUS.value == "mfa_status"

    def test_status_values_are_stable_strings(self) -> None:
        assert IdentityStatus.OK.value == "ok"
        assert IdentityStatus.UNAUTHORIZED.value == "unauthorized"
