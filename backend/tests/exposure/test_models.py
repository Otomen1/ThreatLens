"""Model serialization and classmethod tests for the Exposure Intelligence Framework."""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.entities.types import EntityType
from threatlens.exposure.models import (
    ExposureAsset,
    ExposureCapability,
    ExposureEvidence,
    ExposureFinding,
    ExposureMetadata,
    ExposureProviderMetadata,
    ExposureReference,
    ExposureStatistics,
    ExposureStatus,
    ExposureSummary,
)


class TestExposureProviderMetadata:
    def test_requires_auth_true_for_api_key(self) -> None:
        meta = ExposureProviderMetadata(
            name="shodan",
            display_name="Shodan",
            supported_entity_types=frozenset({EntityType.IPV4}),
        )
        assert meta.requires_auth is True

    def test_requires_auth_false_for_none(self) -> None:
        from threatlens.exposure.models import ExposureAuthType

        meta = ExposureProviderMetadata(
            name="free",
            display_name="Free",
            supported_entity_types=frozenset({EntityType.IPV4}),
            auth_type=ExposureAuthType.NONE,
        )
        assert meta.requires_auth is False


class TestExposureFinding:
    def test_not_found_has_no_error(self) -> None:
        finding = ExposureFinding.not_found(
            provider="shodan", entity_type=EntityType.IPV4, entity_value="8.8.8.8"
        )
        assert finding.status == ExposureStatus.NOT_FOUND
        assert finding.error is None
        assert finding.is_ok is False
        assert finding.has_findings is False

    def test_unsupported(self) -> None:
        finding = ExposureFinding.unsupported(
            provider="shodan", entity_type=EntityType.EMAIL, entity_value="a@b.com"
        )
        assert finding.status == ExposureStatus.UNSUPPORTED

    def test_failure_carries_error(self) -> None:
        finding = ExposureFinding.failure(
            provider="shodan",
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            message="boom",
            detail="stack trace redacted",
        )
        assert finding.is_error is True
        assert finding.error is not None
        assert finding.error.message == "boom"

    def test_ok_finding_with_data_has_findings(self) -> None:
        finding = ExposureFinding(
            provider="shodan",
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            status=ExposureStatus.OK,
            category=ExposureCapability.OPEN_PORTS,
            summary="2 open ports",
            evidence=[ExposureEvidence(type="port", summary="port 22 open")],
            assets=[ExposureAsset(asset_type="open_port", value="22")],
        )
        assert finding.has_findings is True
        assert finding.is_ok is True

    def test_round_trip_serialization(self) -> None:
        finding = ExposureFinding(
            provider="shodan",
            provider_display_name="Shodan",
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            category=ExposureCapability.OPEN_PORTS,
            summary="test",
            references=[ExposureReference(title="t", url="https://x")],
        )
        payload = finding.model_dump_json()
        restored = ExposureFinding.model_validate_json(payload)
        assert restored == finding


class TestExposureSummary:
    def test_round_trip_serialization(self) -> None:
        summary = ExposureSummary(
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            statistics=ExposureStatistics(),
            metadata=ExposureMetadata(
                entity_type=EntityType.IPV4,
                entity_value="8.8.8.8",
                generated_at=datetime.now(UTC),
                framework_version="0.1.0",
            ),
        )
        restored = ExposureSummary.model_validate_json(summary.model_dump_json())
        assert restored == summary

    def test_empty_summary_has_no_findings(self) -> None:
        summary = ExposureSummary(
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            statistics=ExposureStatistics(),
            metadata=ExposureMetadata(
                entity_type=EntityType.IPV4,
                entity_value="8.8.8.8",
                generated_at=datetime.now(UTC),
                framework_version="0.1.0",
            ),
        )
        assert summary.has_findings is False
        assert summary.findings == []
