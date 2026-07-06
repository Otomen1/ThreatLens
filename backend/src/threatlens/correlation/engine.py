"""The Investigation Correlation Engine — a pure, deterministic consumer of
:class:`~threatlens.reasoning.models.InvestigationSummary`.

``correlate(summary)`` runs every registered :class:`CorrelationRule` through a
single generic evaluator, producing higher-level
:class:`~threatlens.correlation.models.CorrelationObservation` objects that
reference the source findings they combine. It then delegates to
``summary.build_correlation_summary`` for deterministic ordering, per-rule
matches, statistics, and identity.

Guarantees (mirroring the Detection and Reasoning Engines):

* **Pure.** No I/O, no providers, no AI, no wall clock — ``generated_at`` is
  inherited from the source summary, so identical input always yields an
  identical output.
* **Read-only.** The ``InvestigationSummary`` is consumed, never mutated. No
  finding, confidence, severity, priority, or recommendation is touched.
* **Never invents evidence.** Every observation references existing findings by
  id; correlation only *combines* what the Reasoning Engine already produced.
* **Content-addressed identity.** Observation and summary ids hash only stable
  values — never timestamps — so the same evidence always maps to the same id.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from ..entities.types import EntityType
from ..reasoning.models import Finding, FindingCategory, InvestigationSummary
from .models import (
    CorrelationEvidence,
    CorrelationObservation,
    CorrelationRelationship,
    CorrelationRule,
    CorrelationSummary,
)
from .registry import CorrelationRegistry, build_default_registry
from .summary import build_correlation_summary

CORRELATION_FRAMEWORK_VERSION = "0.1.0"
"""Pre-1.0: the engine is complete but ships only a small seed rule set (Phase
7.0). Moves to "1.0" once the rule set is expanded and validated end-to-end —
the same "frozen after validation" convention as the Reasoning, Detection, and
Exposure Engines."""


# --------------------------------------------------------------------------- #
# Identity (stable, content-addressed — never includes timestamps)
# --------------------------------------------------------------------------- #


def compute_observation_id(
    *,
    rule_id: str,
    category: str,
    subject_type: str,
    subject_value: str,
    source_finding_ids: Iterable[str],
) -> str:
    """Deterministic, content-addressed observation id.

    Hashes the rule, category, subject, and the sorted source finding ids —
    never a timestamp — so the same correlation always yields the same id.
    """
    ids = sorted({fid.strip() for fid in source_finding_ids if fid.strip()})
    payload = "|".join([rule_id, category, subject_type, subject_value.strip().lower(), *ids])
    return f"cor_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


# --------------------------------------------------------------------------- #
# Rule evaluation (the single generic evaluator every rule shares)
# --------------------------------------------------------------------------- #


def _matching_findings(findings: Sequence[Finding], category: FindingCategory) -> list[Finding]:
    """Findings that carry ``category`` (stable input order preserved)."""
    return [f for f in findings if category in f.categories]


def _sorted_categories(rule: CorrelationRule) -> list[FindingCategory]:
    """The rule's required categories in a stable order (for deterministic pairing)."""
    return sorted(rule.required_categories, key=lambda c: c.value)


def _build_observation(
    rule: CorrelationRule,
    *,
    subject_type: EntityType,
    subject_value: str,
    per_category: dict[FindingCategory, list[Finding]],
) -> CorrelationObservation:
    """Assemble one observation from the findings that satisfied ``rule``."""
    categories = _sorted_categories(rule)

    # Evidence: reference every contributing finding, deduplicated by
    # (finding id, matched category), in a deterministic order.
    evidence: list[CorrelationEvidence] = []
    seen_evidence: set[tuple[str, str]] = set()
    finding_ids: set[str] = set()
    for category in categories:
        for finding in per_category[category]:
            finding_ids.add(finding.id)
            key = (finding.id, category.value)
            if key in seen_evidence:
                continue
            seen_evidence.add(key)
            evidence.append(
                CorrelationEvidence(
                    finding_id=finding.id,
                    matched_category=category,
                    subject_type=finding.subject_type,
                    subject_value=finding.subject_value,
                    summary=finding.title,
                )
            )

    # Relationship: link the first finding of each of the two required
    # categories (deterministic by finding order), unless they are the same
    # finding (a single multi-category finding satisfied both).
    relationships: list[CorrelationRelationship] = []
    first = per_category[categories[0]][0]
    second = per_category[categories[1]][0]
    if first.id != second.id:
        relationships.append(
            CorrelationRelationship(
                type=rule.relationship,
                source_finding_id=first.id,
                target_finding_id=second.id,
                description=rule.name,
            )
        )

    sorted_ids = tuple(sorted(finding_ids))
    observation_id = compute_observation_id(
        rule_id=rule.id,
        category=rule.category.value,
        subject_type=subject_type.value,
        subject_value=subject_value,
        source_finding_ids=sorted_ids,
    )
    return CorrelationObservation(
        id=observation_id,
        rule_id=rule.id,
        category=rule.category,
        title=rule.title,
        summary=rule.description,
        subject_type=subject_type,
        subject_value=subject_value,
        evidence=tuple(evidence),
        relationships=tuple(relationships),
        source_finding_ids=sorted_ids,
    )


def evaluate_rule(
    rule: CorrelationRule, summary: InvestigationSummary
) -> list[CorrelationObservation]:
    """Evaluate one rule against an investigation (pure, deterministic).

    A same-subject rule fires once per subject whose findings jointly cover
    every required category. A cross-subject rule fires once for the whole
    investigation when the categories co-occur anywhere in it.
    """
    findings = summary.findings

    if rule.same_subject:
        subjects: dict[tuple[EntityType, str], list[Finding]] = {}
        for finding in findings:
            subjects.setdefault((finding.subject_type, finding.subject_value), []).append(finding)

        observations: list[CorrelationObservation] = []
        for (subject_type, subject_value), group in sorted(
            subjects.items(), key=lambda kv: (kv[0][0].value, kv[0][1].lower())
        ):
            per_category = {c: _matching_findings(group, c) for c in rule.required_categories}
            if all(per_category[c] for c in rule.required_categories):
                observations.append(
                    _build_observation(
                        rule,
                        subject_type=subject_type,
                        subject_value=subject_value,
                        per_category=per_category,
                    )
                )
        return observations

    per_category = {c: _matching_findings(findings, c) for c in rule.required_categories}
    if all(per_category[c] for c in rule.required_categories):
        return [
            _build_observation(
                rule,
                subject_type=summary.entity_type,
                subject_value=summary.entity_value,
                per_category=per_category,
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #


def correlate(
    summary: InvestigationSummary,
    *,
    registry: CorrelationRegistry | None = None,
) -> CorrelationSummary:
    """Convert an ``InvestigationSummary`` into a ``CorrelationSummary`` (pure).

    Runs each registered rule in priority order, collects the observations, and
    delegates to ``build_correlation_summary`` for deterministic ordering,
    matches, statistics, and identity. With no rule matching (e.g. an empty
    investigation) the result is a well-formed, observation-free summary.
    """
    reg = registry if registry is not None else build_default_registry()

    observations: list[CorrelationObservation] = []
    for rule in reg.rules:  # already priority-then-id ordered
        observations.extend(evaluate_rule(rule, summary))

    return build_correlation_summary(
        observations,
        entity_type=summary.entity_type,
        entity_value=summary.entity_value,
        source_engine_version=summary.engine_version,
        source_finding_ids=[finding.id for finding in summary.findings],
        framework_version=CORRELATION_FRAMEWORK_VERSION,
        generated_at=summary.generated_at,  # inherited — the engine never reads the clock
        rules_evaluated=len(reg),
    )
