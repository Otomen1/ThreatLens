"""The Exposure validation harness — runs each scenario through the real framework.

``run_scenario`` builds a real :class:`ExposureRegistry` from a scenario's fake
providers and drives it through the real, unmodified
:class:`~threatlens.exposure.service.ExposureService` — the same code path
``GET /api/v1/exposure`` uses. ``validate_scenario`` returns a list of failure
strings (empty = pass), shared by the pytest suite so failures read the same
in CI as they would in a report. ``snapshot`` is the golden/determinism
projection.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from typing import Any

from threatlens.exposure.models import ExposureSummary
from threatlens.exposure.registry import ExposureRegistry
from threatlens.exposure.service import ExposureService

from .corpus import Scenario
from .fakes import entity as make_entity

# The exact key sets the frontend (``frontend/lib/api.ts``) and
# ``GET /api/v1/exposure`` both depend on — any drift here is a breaking
# contract change, not an internal refactor.
_SUMMARY_KEYS = {"entity_type", "entity_value", "findings", "references", "statistics", "metadata"}
_FINDING_KEYS = {
    "provider",
    "provider_display_name",
    "entity_type",
    "entity_value",
    "status",
    "error",
    "category",
    "summary",
    "evidence",
    "assets",
    "references",
    "fetched_at",
}
_STATISTICS_KEYS = {
    "providers_queried",
    "providers_ok",
    "total_findings",
    "total_assets",
    "categories",
}
_METADATA_KEYS = {"entity_type", "entity_value", "generated_at", "framework_version"}


def run_scenario(scenario: Scenario) -> ExposureSummary:
    """Run one scenario through the real, unmodified ``ExposureService``."""

    async def _run() -> ExposureSummary:
        registry = ExposureRegistry()
        for provider in scenario.providers:
            registry.register(provider)
        service = ExposureService(registry)
        entity = make_entity(scenario.entity_value, scenario.entity_type)
        return await service.investigate(entity)

    return asyncio.run(_run())


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def validate_scenario(scenario: Scenario) -> list[str]:
    """Validate one scenario end-to-end; return a list of failures ([] = pass)."""
    failures: list[str] = []
    summary = run_scenario(scenario)

    # 1. Routing + merge correctness
    if summary.statistics.providers_queried != scenario.expect_providers_queried:
        failures.append(
            f"providers_queried: got {summary.statistics.providers_queried}, "
            f"expected {scenario.expect_providers_queried}"
        )
    order = tuple(f.provider for f in summary.findings)
    if order != scenario.expect_provider_order:
        failures.append(f"provider order: got {order}, expected {scenario.expect_provider_order}")
    if summary.statistics.providers_ok != scenario.expect_providers_ok:
        failures.append(
            f"providers_ok: got {summary.statistics.providers_ok}, "
            f"expected {scenario.expect_providers_ok}"
        )
    if summary.statistics.total_findings != scenario.expect_total_findings:
        failures.append(
            f"total_findings: got {summary.statistics.total_findings}, "
            f"expected {scenario.expect_total_findings}"
        )
    if summary.statistics.total_assets != scenario.expect_total_assets:
        failures.append(
            f"total_assets: got {summary.statistics.total_assets}, "
            f"expected {scenario.expect_total_assets}"
        )
    if summary.statistics.categories != scenario.expect_categories:
        failures.append(
            f"categories: got {sorted(c.value for c in summary.statistics.categories)}, "
            f"expected {sorted(c.value for c in scenario.expect_categories)}"
        )

    # 2. Entity identity is preserved, never silently changed
    if summary.entity_type != scenario.entity_type or summary.entity_value != scenario.entity_value:
        failures.append("entity identity not preserved on the summary")
    for finding in summary.findings:
        if finding.entity_value != scenario.entity_value:
            failures.append(f"{finding.provider}: entity_value mismatch on finding")

    # 3. No duplicate references (cross-provider, by URL)
    urls = [ref.url for ref in summary.references]
    if len(urls) != len(set(urls)):
        dupes = [url for url, n in Counter(urls).items() if n > 1]
        failures.append(f"duplicate references by URL: {dupes}")

    # 4. No duplicate evidence/assets within any single finding
    for finding in summary.findings:
        ev_keys = [(e.type, e.value) for e in finding.evidence]
        if len(ev_keys) != len(set(ev_keys)):
            failures.append(f"{finding.provider}: duplicate evidence within one finding")
        asset_keys = [(a.asset_type, a.value) for a in finding.assets]
        if len(asset_keys) != len(set(asset_keys)):
            failures.append(f"{finding.provider}: duplicate assets within one finding")

    # 5. Serialization round-trips byte-for-byte (the durable/API contract)
    dumped = summary.model_dump_json()
    restored = ExposureSummary.model_validate_json(dumped)
    if restored != summary:
        failures.append("serialization round-trip mismatch")

    # 6. Frontend/API data contract — exact key sets, no silent drift
    payload = json.loads(dumped)
    if set(payload) != _SUMMARY_KEYS:
        failures.append(f"summary keys drifted: {sorted(payload)}")
    if set(payload.get("statistics", {})) != _STATISTICS_KEYS:
        failures.append("statistics keys drifted")
    if set(payload.get("metadata", {})) != _METADATA_KEYS:
        failures.append("metadata keys drifted")
    for finding_payload in payload.get("findings", []):
        if set(finding_payload) != _FINDING_KEYS:
            failures.append(f"finding keys drifted: {sorted(finding_payload)}")

    return failures


# --------------------------------------------------------------------------- #
# Golden snapshot (excludes wall-clock-derived fields — see architecture review)
# --------------------------------------------------------------------------- #


def snapshot(scenario: Scenario) -> dict[str, Any]:
    """A compact, stable view of a scenario's summary for determinism/golden checks.

    Excludes ``metadata.generated_at`` — the one wall-clock-derived field
    ``ExposureService.investigate()`` produces (it takes no injectable clock).
    Every finding's ``fetched_at`` is fixed by the corpus's fake providers, so
    it is safe to include and does not need the same exclusion.
    """
    summary = run_scenario(scenario)
    return {
        "entity": [summary.entity_type.value, summary.entity_value],
        "statistics": {
            "providers_queried": summary.statistics.providers_queried,
            "providers_ok": summary.statistics.providers_ok,
            "total_findings": summary.statistics.total_findings,
            "total_assets": summary.statistics.total_assets,
            "categories": sorted(c.value for c in summary.statistics.categories),
        },
        "references": sorted(r.url for r in summary.references),
        "findings": [
            {
                "provider": f.provider,
                "status": f.status.value,
                "category": f.category.value if f.category else None,
                "fetched_at": f.fetched_at.isoformat() if f.fetched_at else None,
                "evidence": [[e.type, e.value] for e in f.evidence],
                "assets": [[a.asset_type, a.value] for a in f.assets],
                "references": sorted(r.url for r in f.references),
                "error": f.error.message if f.error else None,
            }
            for f in summary.findings
        ],
    }
