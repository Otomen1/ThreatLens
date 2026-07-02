"""The validation harness — runs each IOC case through the live pipeline.

Detection, normalization, and provider routing are validated against the *live*
engine; reasoning is driven by the case's simulated intelligence. ``validate_case``
returns a list of failure strings (empty = pass) and is shared by the pytest
suite and the report generator, so the report reflects exactly what CI enforces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from time import perf_counter

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType
from threatlens.providers import build_default_router
from threatlens.reasoning import ConfidenceBand, InvestigationSummary, Severity, reason
from threatlens.reference import build_default_reference_router

from .corpus import NOW, IocCase, _empty

_TI_ROUTER = build_default_router()
_REF_ROUTER = build_default_reference_router()

# Expected provider routing per entity type (ground truth probed from the engine).
_EXPECTED_TI: dict[EntityType, frozenset[str]] = {
    EntityType.IPV4: frozenset({"abuseipdb", "otx"}),
    EntityType.IPV6: frozenset({"abuseipdb", "otx"}),
    EntityType.DOMAIN: frozenset({"urlhaus", "otx"}),
    EntityType.URL: frozenset({"urlhaus", "otx"}),
    EntityType.MD5: frozenset({"malwarebazaar", "otx"}),
    EntityType.SHA1: frozenset({"malwarebazaar", "otx"}),
    EntityType.SHA256: frozenset({"malwarebazaar", "otx"}),
}
_EXPECTED_REF: dict[EntityType, frozenset[str]] = {
    EntityType.CVE: frozenset({"nvd"}),
    EntityType.CWE: frozenset({"cwe"}),
    EntityType.CAPEC: frozenset({"capec"}),
    EntityType.MITRE_TECHNIQUE: frozenset({"mitre_attack"}),
    EntityType.THREAT_ACTOR: frozenset({"mitre_attack"}),
    EntityType.MALWARE_FAMILY: frozenset({"mitre_attack"}),
}


def detect_entity(case: IocCase) -> Entity:
    """Detect the entity for a case via the live engine."""
    from threatlens.search import detect

    return detect(case.query)


def routed_names(entity: Entity) -> tuple[frozenset[str], frozenset[str]]:
    """The provider names the live routers select for ``entity`` (TI, reference)."""
    ti = frozenset(p.metadata.name for p in _TI_ROUTER.route(entity))
    ref = frozenset(p.metadata.name for p in _REF_ROUTER.route(entity))
    return ti, ref


def summary_for(case: IocCase, *, now: datetime = NOW) -> InvestigationSummary:
    """Build the InvestigationSummary for a case (detect + reason)."""
    entity = detect_entity(case)
    ti = case.ti or _empty(entity.type, entity.value)
    knowledge = case.knowledge or _empty(entity.type, entity.value)
    return reason(entity, ti, knowledge, now=now)


def has_providers(entity_type: EntityType) -> bool:
    """Whether any investigation provider supports this entity type."""
    return bool(_EXPECTED_TI.get(entity_type) or _EXPECTED_REF.get(entity_type))


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def validate_case(case: IocCase) -> list[str]:
    """Validate one case end-to-end; return a list of failures ([] = pass)."""
    failures: list[str] = []
    entity = detect_entity(case)

    # 1. Detection + normalization
    if entity.type is not case.expected_type:
        failures.append(f"detection: got {entity.type.value}, expected {case.expected_type.value}")
    if case.expected_normalized is not None and entity.value != case.expected_normalized:
        failures.append(
            f"normalization: got {entity.value!r}, expected {case.expected_normalized!r}"
        )

    # 2. Provider routing (validated against the live routers)
    ti_names, ref_names = routed_names(entity)
    if ti_names != _EXPECTED_TI.get(entity.type, frozenset()):
        failures.append(f"ti routing: got {sorted(ti_names)}")
    if ref_names != _EXPECTED_REF.get(entity.type, frozenset()):
        failures.append(f"reference routing: got {sorted(ref_names)}")

    # Input correctly rejected upstream — no summary is produced or expected.
    if case.api_status != 200:
        return failures

    # 3. Reasoning + summary well-formedness (the frontend data contract)
    summary = summary_for(case)
    failures.extend(_validate_summary_shape(summary))

    # 4. Declarative reasoning expectations (the golden pins exact values)
    if case.expect_findings is not None and len(summary.findings) != case.expect_findings:
        failures.append(f"findings: got {len(summary.findings)}, expected {case.expect_findings}")
    if case.expect_posture is not None and summary.posture is not case.expect_posture:
        failures.append(f"posture: got {summary.posture.name}, expected {case.expect_posture.name}")
    present = {cat for finding in summary.findings for cat in finding.categories}
    missing = case.expect_categories - present
    if missing:
        failures.append(f"categories missing: {sorted(c.value for c in missing)}")
    if (
        case.expect_min_recommendations is not None
        and len(summary.recommendations) < case.expect_min_recommendations
    ):
        failures.append(
            f"recommendations: got {len(summary.recommendations)}, "
            f"expected >= {case.expect_min_recommendations}"
        )
    if (
        case.expect_overall_band is not None
        and summary.overall_confidence.band is not case.expect_overall_band
    ):
        failures.append(
            f"overall band: got {summary.overall_confidence.band.value}, "
            f"expected {case.expect_overall_band.value}"
        )

    return failures


def _validate_summary_shape(summary: InvestigationSummary) -> list[str]:
    """Invariants every InvestigationSummary must satisfy (frontend-renderable)."""
    failures: list[str] = []
    if not isinstance(summary.posture, Severity):
        failures.append("posture is not a Severity")
    conf = summary.overall_confidence
    if not (0 <= conf.score <= 100):
        failures.append(f"overall confidence score out of range: {conf.score}")
    if not isinstance(conf.band, ConfidenceBand):
        failures.append("overall confidence band invalid")

    finding_ids = {finding.id for finding in summary.findings}
    for finding in summary.findings:
        if not finding.id.startswith("fnd_"):
            failures.append(f"finding id malformed: {finding.id}")
        if not finding.categories:
            failures.append(f"finding {finding.id} has no categories")
        if not finding.subject_value:
            failures.append(f"finding {finding.id} has empty subject_value")
        if finding.priority < 0:
            failures.append(f"finding {finding.id} negative priority")
        if not (0 <= finding.confidence.score <= 100):
            failures.append(f"finding {finding.id} confidence out of range")
    for rec in summary.recommendations:
        if rec.priority < 0:
            failures.append("recommendation negative priority")
        if not rec.target_value:
            failures.append("recommendation empty target_value")
        # Rollup recommendations must trace back to real findings (grounding).
        if finding_ids and not (set(rec.finding_ids) <= finding_ids):
            failures.append(f"recommendation references unknown finding ids: {rec.finding_ids}")
    return failures


# --------------------------------------------------------------------------- #
# Metrics (for the validation report)
# --------------------------------------------------------------------------- #


@dataclass
class CaseOutcome:
    """The measured result of running one case (for the report)."""

    id: str
    category: str
    entity_type: str
    outcome: str  # success | no_findings | unsupported | rejected | failed
    findings: int
    posture: int
    overall_band: str
    recommendations: int
    relationships: int
    references: int
    detect_us: float
    reason_us: float
    failures: list[str] = field(default_factory=list)


def run_case(case: IocCase) -> CaseOutcome:
    """Run a case, measuring latency and classifying the outcome."""
    failures = validate_case(case)

    t0 = perf_counter()
    entity = detect_entity(case)
    detect_us = (perf_counter() - t0) * 1e6

    if case.api_status != 200:
        return CaseOutcome(
            case.id,
            case.category,
            entity.type.value,
            "rejected",
            0,
            0,
            "n/a",
            0,
            0,
            0,
            detect_us,
            0.0,
            failures,
        )

    t0 = perf_counter()
    summary = summary_for(case)
    reason_us = (perf_counter() - t0) * 1e6

    if failures:
        outcome = "failed"
    elif not has_providers(entity.type):
        outcome = "unsupported"
    elif summary.findings:
        outcome = "success"
    else:
        outcome = "no_findings"

    return CaseOutcome(
        id=case.id,
        category=case.category,
        entity_type=entity.type.value,
        outcome=outcome,
        findings=len(summary.findings),
        posture=int(summary.posture),
        overall_band=summary.overall_confidence.band.value,
        recommendations=len(summary.recommendations),
        relationships=sum(len(f.relationships) for f in summary.findings),
        references=0,
        detect_us=detect_us,
        reason_us=reason_us,
        failures=failures,
    )


def run_corpus(corpus: tuple[IocCase, ...]) -> list[CaseOutcome]:
    """Run every case and return per-case outcomes."""
    return [run_case(case) for case in corpus]
