"""Validation & snapshot harness for the Detection Engine freeze suite.

For each scenario it runs the full generator set and checks the freeze
invariants (determinism, deterministic/timestamp-independent ids, unique rules,
provenance, ATT&CK mapping, parser-level validity, serialization, and the
frontend/API contract), then produces a stable snapshot for golden regression.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from threatlens.detection import DetectionPackage, generate

from .corpus import Scenario
from .validate import validate_rule

_FRONTEND_KEYS = {"id", "metadata", "artifacts", "languages", "source_finding_ids"}
_ARTIFACT_KEYS = {"id", "language", "target", "title", "content", "severity", "category"}
_ALT_TIME = datetime(2030, 1, 1, tzinfo=UTC)


def validate_scenario(scenario: Scenario) -> list[str]:
    """Return a list of invariant violations (empty means the scenario passes)."""
    problems: list[str] = []
    summary = scenario.summary
    pkg = generate(summary)

    if generate(summary) != pkg:
        problems.append("nondeterministic package")

    if scenario.expect_empty and pkg.artifacts:
        problems.append(f"expected no artifacts, got {len(pkg.artifacts)}")

    ids = [a.id for a in pkg.artifacts]
    if len(ids) != len(set(ids)):
        problems.append("duplicate artifact ids")

    finding_ids = {f.id for f in summary.findings}
    for artifact in pkg.artifacts:
        tag = artifact.language.value
        if not artifact.id.startswith("det_"):
            problems.append(f"{tag}: bad id prefix")
        if not artifact.rule_id:
            problems.append(f"{tag}: missing rule_id")
        if artifact.metadata.get("detection_id") != artifact.id:
            problems.append(f"{tag}: detection_id != id")
        if not artifact.metadata.get("finding_ids"):
            problems.append(f"{tag}: no finding_ids metadata")
        if not set(artifact.source_finding_ids) <= finding_ids:
            problems.append(f"{tag}: source finding id leak")
        # ATT&CK mapping is reflected in the rule text when present.
        mitre = artifact.metadata.get("attack") or artifact.metadata.get("mitre")
        if mitre:
            for technique in mitre.split(","):
                if technique not in artifact.content and technique.lower() not in artifact.content:
                    problems.append(f"{tag}: technique {technique} absent from rule")
        ok, reason = validate_rule(artifact.language, artifact.content)
        if not ok:
            problems.append(f"{tag}: invalid rule ({reason})")

    if DetectionPackage.model_validate_json(pkg.model_dump_json()) != pkg:
        problems.append("serialization round-trip mismatch")

    dumped = pkg.model_dump(mode="json")
    if not set(dumped) >= _FRONTEND_KEYS:
        problems.append("package missing frontend keys")
    for artifact in dumped["artifacts"]:
        if not set(artifact) >= _ARTIFACT_KEYS:
            problems.append("artifact missing frontend keys")
            break

    # Identity is timestamp-independent (only generated_at differs).
    alt = generate(summary.model_copy(update={"generated_at": _ALT_TIME}))
    if alt.id != pkg.id or [a.id for a in alt.artifacts] != ids:
        problems.append("ids not timestamp-independent")

    return problems


def snapshot(scenario: Scenario) -> dict[str, Any]:
    """A stable, diffable snapshot of a scenario's full generated output."""
    pkg = generate(scenario.summary)
    return {
        "package_id": pkg.id,
        "languages": [lang.value for lang in pkg.languages],
        "source_finding_ids": list(pkg.source_finding_ids),
        "artifacts": [
            {
                "id": a.id,
                "language": a.language.value,
                "category": a.category.value,
                "severity": int(a.severity),
                "rule_id": a.rule_id,
                "validation": a.validation.status.value,
                "finding_ids": a.metadata.get("finding_ids", ""),
                "attack": a.metadata.get("attack") or a.metadata.get("mitre") or "",
                "sha256": hashlib.sha256(a.content.encode()).hexdigest()[:16],
            }
            for a in pkg.artifacts
        ],
    }
