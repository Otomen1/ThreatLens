"""Tests for identity.summary: merge_findings / merge_assets aggregation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from threatlens.entities.types import EntityType
from threatlens.identity.models import (
    IdentityAsset,
    IdentityCapability,
    IdentityFinding,
    IdentityReference,
    IdentityStatus,
    IdentitySummary,
)
from threatlens.identity.summary import merge_assets, merge_findings

_NOW = datetime(2024, 1, 1, tzinfo=UTC)
_ENTITY_TYPE = EntityType.EMAIL
_ENTITY_VALUE = "a@b.com"


def _merge(findings: Sequence[IdentityFinding]) -> IdentitySummary:
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
    category: IdentityCapability = IdentityCapability.BREACHES,
    assets: list[IdentityAsset] | None = None,
    references: list[IdentityReference] | None = None,
) -> IdentityFinding:
    return IdentityFinding(
        provider=provider,
        entity_type=_ENTITY_TYPE,
        entity_value=_ENTITY_VALUE,
        status=IdentityStatus.OK,
        category=category,
        summary="found something",
        assets=assets or [IdentityAsset(asset_type="breached_account", value="a@b.com")],
        references=references or [],
    )


def _not_found(provider: str) -> IdentityFinding:
    return IdentityFinding.not_found(
        provider=provider, entity_type=_ENTITY_TYPE, entity_value=_ENTITY_VALUE
    )


def _failure(provider: str, message: str) -> IdentityFinding:
    return IdentityFinding.failure(
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
        summary = _merge([_ok_finding("hibp"), _not_found("okta"), _failure("entra", "down")])
        assert summary.statistics.providers_queried == 3
        assert summary.statistics.providers_ok == 1
        assert summary.statistics.total_findings == 1  # only the OK finding has_findings
        assert len(summary.findings) == 3  # every provider's attribution is kept

    def test_total_assets_sums_across_findings(self) -> None:
        summary = _merge(
            [
                _ok_finding(
                    "hibp", assets=[IdentityAsset(asset_type="breached_account", value="x")]
                ),
                _ok_finding(
                    "entra",
                    category=IdentityCapability.DIRECTORY_PROFILE,
                    assets=[
                        IdentityAsset(asset_type="directory_account", value="u1"),
                        IdentityAsset(asset_type="directory_account", value="u2"),
                    ],
                ),
            ]
        )
        assert summary.statistics.total_assets == 3

    def test_categories_reflect_findings_with_data_only(self) -> None:
        summary = _merge(
            [_ok_finding("hibp", category=IdentityCapability.BREACHES), _not_found("okta")]
        )
        assert summary.statistics.categories == frozenset({IdentityCapability.BREACHES})


class TestMergeReferences:
    def test_deduplicates_references_by_url_across_providers(self) -> None:
        shared = IdentityReference(title="shared", url="https://x.example/shared")
        summary = _merge(
            [_ok_finding("hibp", references=[shared]), _ok_finding("okta", references=[shared])]
        )
        assert len(summary.references) == 1


class TestMergeAssets:
    def test_deduplicates_by_asset_type_and_value(self) -> None:
        findings = [
            _ok_finding("hibp", assets=[IdentityAsset(asset_type="breached_account", value="x")]),
            _ok_finding("okta", assets=[IdentityAsset(asset_type="breached_account", value="x")]),
        ]
        assets = merge_assets(findings)
        assert len(assets) == 1

    def test_empty_input_yields_empty_list(self) -> None:
        assert merge_assets([]) == []
