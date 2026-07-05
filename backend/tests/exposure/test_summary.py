"""Tests for exposure.summary: merge_findings / merge_assets aggregation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from threatlens.entities.types import EntityType
from threatlens.exposure.models import (
    ExposureAsset,
    ExposureCapability,
    ExposureFinding,
    ExposureReference,
    ExposureStatus,
    ExposureSummary,
)
from threatlens.exposure.summary import merge_assets, merge_findings

_NOW = datetime(2024, 1, 1, tzinfo=UTC)
_ENTITY_TYPE = EntityType.IPV4
_ENTITY_VALUE = "8.8.8.8"


def _merge(findings: Sequence[ExposureFinding]) -> ExposureSummary:
    return merge_findings(
        findings,
        entity_type=_ENTITY_TYPE,
        entity_value=_ENTITY_VALUE,
        framework_version="0.1.0",
        now=_NOW,
    )


def _ok_finding(
    provider: str,
    *,
    category: ExposureCapability = ExposureCapability.OPEN_PORTS,
    assets: list[ExposureAsset] | None = None,
    references: list[ExposureReference] | None = None,
) -> ExposureFinding:
    return ExposureFinding(
        provider=provider,
        entity_type=_ENTITY_TYPE,
        entity_value=_ENTITY_VALUE,
        status=ExposureStatus.OK,
        category=category,
        summary="found something",
        assets=assets or [ExposureAsset(asset_type="open_port", value="22")],
        references=references or [],
    )


def _not_found(provider: str) -> ExposureFinding:
    return ExposureFinding.not_found(
        provider=provider, entity_type=_ENTITY_TYPE, entity_value=_ENTITY_VALUE
    )


def _failure(provider: str, message: str) -> ExposureFinding:
    return ExposureFinding.failure(
        provider=provider, entity_type=_ENTITY_TYPE, entity_value=_ENTITY_VALUE, message=message
    )


class TestMergeFindingsEmpty:
    def test_empty_input_yields_empty_well_formed_summary(self) -> None:
        summary = _merge([])
        assert summary.findings == []
        assert summary.statistics.providers_queried == 0
        assert summary.statistics.providers_ok == 0
        assert summary.statistics.total_findings == 0
        assert summary.statistics.total_assets == 0
        assert summary.metadata.framework_version == "0.1.0"
        assert summary.metadata.generated_at == _NOW


class TestMergeFindingsStatistics:
    def test_counts_providers_queried_regardless_of_outcome(self) -> None:
        summary = _merge(
            [_ok_finding("shodan"), _not_found("censys"), _failure("greynoise", "down")]
        )
        assert summary.statistics.providers_queried == 3
        assert summary.statistics.providers_ok == 1
        assert summary.statistics.total_findings == 1  # only the OK finding has_findings
        assert len(summary.findings) == 3  # every provider's attribution is kept

    def test_total_assets_sums_across_findings(self) -> None:
        summary = _merge(
            [
                _ok_finding("shodan", assets=[ExposureAsset(asset_type="open_port", value="22")]),
                _ok_finding(
                    "censys",
                    category=ExposureCapability.CERTIFICATES,
                    assets=[
                        ExposureAsset(asset_type="certificate", value="cert1"),
                        ExposureAsset(asset_type="certificate", value="cert2"),
                    ],
                ),
            ]
        )
        assert summary.statistics.total_assets == 3

    def test_categories_reflect_findings_with_data_only(self) -> None:
        summary = _merge(
            [_ok_finding("shodan", category=ExposureCapability.OPEN_PORTS), _not_found("censys")]
        )
        assert summary.statistics.categories == frozenset({ExposureCapability.OPEN_PORTS})


class TestMergeReferences:
    def test_deduplicates_references_by_url_across_providers(self) -> None:
        shared = ExposureReference(title="shared", url="https://x.example/shared")
        summary = _merge(
            [_ok_finding("shodan", references=[shared]), _ok_finding("censys", references=[shared])]
        )
        assert len(summary.references) == 1


class TestMergeAssets:
    def test_deduplicates_by_asset_type_and_value(self) -> None:
        findings = [
            _ok_finding("shodan", assets=[ExposureAsset(asset_type="open_port", value="22")]),
            _ok_finding("censys", assets=[ExposureAsset(asset_type="open_port", value="22")]),
        ]
        assets = merge_assets(findings)
        assert len(assets) == 1

    def test_empty_input_yields_empty_list(self) -> None:
        assert merge_assets([]) == []
