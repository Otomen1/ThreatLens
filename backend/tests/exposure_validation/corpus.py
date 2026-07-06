"""The Exposure Engine validation corpus (Phase 5.4) — ~150 scenarios.

Built parametrically (mirroring ``tests/detection/corpus.py``): 12 realistic
category labels x 12 provider-matrix "shapes" (every single/pair/triple
provider combination, disabled providers, timeout, auth failure, malformed
response, mixed outcomes) = 144 scenarios, plus ~9 standalone special cases
(empty registry, unsupported entity type, a provider that raises, all-
not-found, all-rate-limited, cross-provider reference de-duplication, IPv6
routing excluding GreyNoise, a large finding, and a non-default-priority
ordering check).

Entity values use only RFC 5737 documentation ranges (``192.0.2.0/24``) —
never a real allocated IP — since every "category" here (including
"known malicious host") is just a descriptive label on a synthetic address
attached to an entirely canned finding; no real-world host is ever named.

Every provider is a :class:`~fakes.FakeExposureProvider` carrying the real
provider names (``shodan``, ``censys``, ``greynoise``) so ordering exercises
the real priority-then-name tiebreak, but returns only canned findings — no
network, no HTTP mocking. Real per-provider parsing/auth/HTTP-mapping
correctness is already covered by ``tests/exposure/test_*_provider.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.entities.types import EntityType
from threatlens.exposure.models import ExposureCapability, ExposureStatus

from .fakes import FakeExposureProvider, failure_finding, not_found_finding, ok_finding

# Each real provider's success category, chosen to mirror its real specialty
# so cross-category aggregation (``summary.statistics.categories``) is a
# meaningful, multi-valued check rather than one repeated value.
_CATEGORY_BY_NAME = {
    "shodan": ExposureCapability.OPEN_PORTS,
    "censys": ExposureCapability.CERTIFICATES,
    "greynoise": ExposureCapability.INTERNET_NOISE,
}

_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("public_infrastructure", "192.0.2.10"),
    ("cloud_provider", "192.0.2.11"),
    ("cdn", "192.0.2.12"),
    ("vpn", "192.0.2.13"),
    ("internet_scanner", "192.0.2.14"),
    ("known_malicious", "192.0.2.15"),
    ("known_benign", "192.0.2.16"),
    ("residential", "192.0.2.17"),
    ("enterprise", "192.0.2.18"),
    ("government", "192.0.2.19"),
    ("university", "192.0.2.20"),
    ("hosting_provider", "192.0.2.21"),
)

# Each shape: (shape_name, tuple of (provider_name, enabled, outcome|None)).
# outcome is one of "ok" | "timeout" | "unauthorized" | "not_found" | "malformed"
# | None (disabled — never queried, so no outcome needed).
_SHAPES: tuple[tuple[str, tuple[tuple[str, bool, str | None], ...]], ...] = (
    ("shodan_only", (("shodan", True, "ok"),)),
    ("censys_only", (("censys", True, "ok"),)),
    ("greynoise_only", (("greynoise", True, "ok"),)),
    ("shodan_censys", (("shodan", True, "ok"), ("censys", True, "ok"))),
    ("shodan_greynoise", (("shodan", True, "ok"), ("greynoise", True, "ok"))),
    ("censys_greynoise", (("censys", True, "ok"), ("greynoise", True, "ok"))),
    (
        "all_three_success",
        (("shodan", True, "ok"), ("censys", True, "ok"), ("greynoise", True, "ok")),
    ),
    (
        "one_enabled_two_disabled",
        (("shodan", True, "ok"), ("censys", False, None), ("greynoise", False, None)),
    ),
    (
        "all_disabled",
        (("shodan", False, None), ("censys", False, None), ("greynoise", False, None)),
    ),
    (
        "one_timeout_rest_ok",
        (("shodan", True, "ok"), ("censys", True, "timeout"), ("greynoise", True, "ok")),
    ),
    (
        "one_auth_failure_rest_ok",
        (("shodan", True, "ok"), ("censys", True, "ok"), ("greynoise", True, "unauthorized")),
    ),
    (
        "mixed_outcomes",
        (("shodan", True, "ok"), ("censys", True, "not_found"), ("greynoise", True, "malformed")),
    ),
)


@dataclass(frozen=True)
class Scenario:
    """One deterministic corpus case: a set of registered providers + expectations."""

    id: str
    category: str
    entity_type: EntityType
    entity_value: str
    providers: tuple[FakeExposureProvider, ...]
    expect_providers_queried: int
    expect_provider_order: tuple[str, ...]
    expect_providers_ok: int
    expect_total_findings: int
    expect_total_assets: int
    expect_categories: frozenset[ExposureCapability]


def _finding_for(name: str, outcome: str, entity_value: str) -> object:
    if outcome == "ok":
        return ok_finding(name, entity_value=entity_value, category=_CATEGORY_BY_NAME[name])
    if outcome == "timeout":
        return failure_finding(
            name,
            ExposureStatus.TIMEOUT,
            f"{name} request timed out",
            entity_value=entity_value,
            retryable=True,
        )
    if outcome == "unauthorized":
        return failure_finding(
            name,
            ExposureStatus.UNAUTHORIZED,
            f"{name} rejected the API key",
            entity_value=entity_value,
        )
    if outcome == "not_found":
        return not_found_finding(name, entity_value=entity_value)
    if outcome == "malformed":
        return failure_finding(
            name,
            ExposureStatus.ERROR,
            f"{name} returned malformed JSON",
            entity_value=entity_value,
        )
    raise ValueError(f"unknown outcome: {outcome}")  # pragma: no cover - corpus authoring error


def _build(
    scenario_id: str,
    category: str,
    entity_value: str,
    spec: tuple[tuple[str, bool, str | None], ...],
    *,
    entity_type: EntityType = EntityType.IPV4,
) -> Scenario:
    providers: list[FakeExposureProvider] = []
    queried: list[str] = []
    ok_names: list[str] = []
    categories: set[ExposureCapability] = set()

    for name, enabled, outcome in spec:
        finding = _finding_for(name, outcome, entity_value) if outcome is not None else None
        providers.append(FakeExposureProvider(name, enabled=enabled, finding=finding))  # type: ignore[arg-type]
        if enabled:
            queried.append(name)
            if outcome == "ok":
                ok_names.append(name)
                categories.add(_CATEGORY_BY_NAME[name])

    return Scenario(
        id=scenario_id,
        category=category,
        entity_type=entity_type,
        entity_value=entity_value,
        providers=tuple(providers),
        expect_providers_queried=len(queried),
        expect_provider_order=tuple(sorted(queried)),
        expect_providers_ok=len(ok_names),
        expect_total_findings=len(ok_names),  # only "ok" outcomes carry evidence in this corpus
        expect_total_assets=0,
        expect_categories=frozenset(categories),
    )


# --------------------------------------------------------------------------- #
# Special, standalone scenarios (not part of the category x shape grid)
# --------------------------------------------------------------------------- #


def _special_empty_registry() -> Scenario:
    return Scenario(
        id="special__empty_registry",
        category="special",
        entity_type=EntityType.IPV4,
        entity_value="192.0.2.100",
        providers=(),
        expect_providers_queried=0,
        expect_provider_order=(),
        expect_providers_ok=0,
        expect_total_findings=0,
        expect_total_assets=0,
        expect_categories=frozenset(),
    )


def _special_unsupported_entity_type() -> Scenario:
    providers = tuple(
        FakeExposureProvider(name, finding=ok_finding(name, category=_CATEGORY_BY_NAME[name]))
        for name in ("censys", "greynoise", "shodan")
    )
    return Scenario(
        id="special__unsupported_entity_type",
        category="special",
        entity_type=EntityType.DOMAIN,
        entity_value="evil.example.test",
        providers=providers,
        expect_providers_queried=0,
        expect_provider_order=(),
        expect_providers_ok=0,
        expect_total_findings=0,
        expect_total_assets=0,
        expect_categories=frozenset(),
    )


def _special_provider_raises_exception() -> Scenario:
    entity_value = "192.0.2.101"
    providers = (
        FakeExposureProvider(
            "shodan",
            finding=ok_finding(
                "shodan", entity_value=entity_value, category=_CATEGORY_BY_NAME["shodan"]
            ),
        ),
        FakeExposureProvider("censys", raises=RuntimeError("simulated provider crash")),
        FakeExposureProvider(
            "greynoise",
            finding=ok_finding(
                "greynoise", entity_value=entity_value, category=_CATEGORY_BY_NAME["greynoise"]
            ),
        ),
    )
    return Scenario(
        id="special__provider_raises_exception",
        category="special",
        entity_type=EntityType.IPV4,
        entity_value=entity_value,
        providers=providers,
        expect_providers_queried=3,  # censys is queried; safe_lookup converts the raise
        expect_provider_order=("censys", "greynoise", "shodan"),
        expect_providers_ok=2,
        expect_total_findings=2,
        expect_total_assets=0,
        expect_categories=frozenset({_CATEGORY_BY_NAME["shodan"], _CATEGORY_BY_NAME["greynoise"]}),
    )


def _special_all_not_found() -> Scenario:
    entity_value = "192.0.2.102"
    providers = tuple(
        FakeExposureProvider(name, finding=not_found_finding(name, entity_value=entity_value))
        for name in ("censys", "greynoise", "shodan")
    )
    return Scenario(
        id="special__all_not_found",
        category="special",
        entity_type=EntityType.IPV4,
        entity_value=entity_value,
        providers=providers,
        expect_providers_queried=3,
        expect_provider_order=("censys", "greynoise", "shodan"),
        expect_providers_ok=0,
        expect_total_findings=0,
        expect_total_assets=0,
        expect_categories=frozenset(),
    )


def _special_all_rate_limited() -> Scenario:
    entity_value = "192.0.2.103"
    providers = tuple(
        FakeExposureProvider(
            name,
            finding=failure_finding(
                name,
                ExposureStatus.RATE_LIMITED,
                f"{name} rate limit reached",
                entity_value=entity_value,
                retryable=True,
            ),
        )
        for name in ("censys", "greynoise", "shodan")
    )
    return Scenario(
        id="special__all_rate_limited",
        category="special",
        entity_type=EntityType.IPV4,
        entity_value=entity_value,
        providers=providers,
        expect_providers_queried=3,
        expect_provider_order=("censys", "greynoise", "shodan"),
        expect_providers_ok=0,
        expect_total_findings=0,
        expect_total_assets=0,
        expect_categories=frozenset(),
    )


_SHARED_REFERENCE_URL = "https://intel.example.test/report/192.0.2.104"


def _special_duplicate_reference_dedup() -> Scenario:
    from threatlens.exposure.models import ExposureReference

    entity_value = "192.0.2.104"
    ref = ExposureReference(title="Shared report", url=_SHARED_REFERENCE_URL)
    providers = (
        FakeExposureProvider(
            "shodan",
            finding=ok_finding(
                "shodan",
                entity_value=entity_value,
                category=_CATEGORY_BY_NAME["shodan"],
                references=(ref,),
            ),
        ),
        FakeExposureProvider(
            "censys",
            finding=ok_finding(
                "censys",
                entity_value=entity_value,
                category=_CATEGORY_BY_NAME["censys"],
                references=(ref,),
            ),
        ),
    )
    return Scenario(
        id="special__duplicate_reference_dedup",
        category="special",
        entity_type=EntityType.IPV4,
        entity_value=entity_value,
        providers=providers,
        expect_providers_queried=2,
        expect_provider_order=("censys", "shodan"),
        expect_providers_ok=2,
        expect_total_findings=2,
        expect_total_assets=0,
        expect_categories=frozenset({_CATEGORY_BY_NAME["shodan"], _CATEGORY_BY_NAME["censys"]}),
    )


def _special_ipv6_excludes_greynoise() -> Scenario:
    entity_value = "2001:db8::104"
    ipv4_ipv6 = frozenset({EntityType.IPV4, EntityType.IPV6})
    ipv4_only = frozenset({EntityType.IPV4})
    providers = (
        FakeExposureProvider(
            "shodan",
            entity_types=ipv4_ipv6,
            finding=ok_finding(
                "shodan",
                entity_type=EntityType.IPV6,
                entity_value=entity_value,
                category=_CATEGORY_BY_NAME["shodan"],
            ),
        ),
        FakeExposureProvider(
            "censys",
            entity_types=ipv4_ipv6,
            finding=ok_finding(
                "censys",
                entity_type=EntityType.IPV6,
                entity_value=entity_value,
                category=_CATEGORY_BY_NAME["censys"],
            ),
        ),
        # GreyNoise is IPv4-only in reality; the fake mirrors that scope so
        # routing exclusion is exercised the same way it is in production.
        FakeExposureProvider("greynoise", entity_types=ipv4_only, finding=None),
    )
    return Scenario(
        id="special__ipv6_excludes_greynoise",
        category="special",
        entity_type=EntityType.IPV6,
        entity_value=entity_value,
        providers=providers,
        expect_providers_queried=2,
        expect_provider_order=("censys", "shodan"),
        expect_providers_ok=2,
        expect_total_findings=2,
        expect_total_assets=0,
        expect_categories=frozenset({_CATEGORY_BY_NAME["shodan"], _CATEGORY_BY_NAME["censys"]}),
    )


def _special_large_finding() -> Scenario:
    from threatlens.exposure.models import ExposureAsset, ExposureEvidence

    entity_value = "192.0.2.105"
    evidence = tuple(
        ExposureEvidence(type=f"fact_{i}", summary=f"synthetic fact #{i}", value=str(i))
        for i in range(20)
    )
    assets = tuple(ExposureAsset(asset_type="open_port", value=str(1000 + i)) for i in range(15))
    providers = (
        FakeExposureProvider(
            "shodan",
            finding=ok_finding(
                "shodan",
                entity_value=entity_value,
                category=_CATEGORY_BY_NAME["shodan"],
                evidence=evidence,
                assets=assets,
            ),
        ),
    )
    return Scenario(
        id="special__large_finding",
        category="special",
        entity_type=EntityType.IPV4,
        entity_value=entity_value,
        providers=providers,
        expect_providers_queried=1,
        expect_provider_order=("shodan",),
        expect_providers_ok=1,
        expect_total_findings=1,
        expect_total_assets=15,
        expect_categories=frozenset({_CATEGORY_BY_NAME["shodan"]}),
    )


def _special_priority_overrides_name_order() -> Scenario:
    entity_value = "192.0.2.106"
    providers = (
        # Alphabetically "censys" < "shodan", but shodan's lower priority
        # number must still win — proving ordering is priority-then-name,
        # never name-only (the 144-grid, all at the default priority=100,
        # cannot exercise this branch on its own).
        FakeExposureProvider(
            "censys",
            priority=200,
            finding=ok_finding(
                "censys", entity_value=entity_value, category=_CATEGORY_BY_NAME["censys"]
            ),
        ),
        FakeExposureProvider(
            "shodan",
            priority=10,
            finding=ok_finding(
                "shodan", entity_value=entity_value, category=_CATEGORY_BY_NAME["shodan"]
            ),
        ),
    )
    return Scenario(
        id="special__priority_overrides_name_order",
        category="special",
        entity_type=EntityType.IPV4,
        entity_value=entity_value,
        providers=providers,
        expect_providers_queried=2,
        expect_provider_order=("shodan", "censys"),  # priority 10 before 200
        expect_providers_ok=2,
        expect_total_findings=2,
        expect_total_assets=0,
        expect_categories=frozenset({_CATEGORY_BY_NAME["shodan"], _CATEGORY_BY_NAME["censys"]}),
    )


_SPECIALS: tuple[Scenario, ...] = (
    _special_empty_registry(),
    _special_unsupported_entity_type(),
    _special_provider_raises_exception(),
    _special_all_not_found(),
    _special_all_rate_limited(),
    _special_duplicate_reference_dedup(),
    _special_ipv6_excludes_greynoise(),
    _special_large_finding(),
    _special_priority_overrides_name_order(),
)


def _all_scenarios() -> tuple[Scenario, ...]:
    grid: list[Scenario] = []
    for category, entity_value in _CATEGORIES:
        for shape_name, spec in _SHAPES:
            grid.append(_build(f"{category}__{shape_name}", category, entity_value, spec))
    return tuple(grid) + _SPECIALS


CORPUS: tuple[Scenario, ...] = _all_scenarios()
