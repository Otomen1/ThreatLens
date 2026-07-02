"""YARA detection generator — file-based detections (Phase 4.2).

A pure, deterministic :class:`~threatlens.detection.registry.DetectionGenerator`
that converts an ``InvestigationSummary``'s findings into YARA rules. It consumes
**only** ``Finding`` objects — never providers, raw TI, WHOIS, NVD/MITRE JSON, or
any API payload. No AI, no network, no wall clock.

YARA detects *files*, so this generator emits rules **only** for findings whose
subject is a concrete file hash (MD5/SHA1/SHA256) — a valid, non-speculative,
file-based match via YARA's ``hash`` module. It never produces IOC-style rules
(no IPs, domains, or URLs), and it never matches on a bare malware-family name
(insufficient information → no rule; a weak rule is worse than none).

Identity is deterministic and timestamp-independent: the rule name and ``rule_id``
hash only the file hash; the framework artifact id hashes the rule structure
excluding the ``date``. No randomness, no UUID4.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from datetime import datetime

from ... import __version__ as THREATLENS_VERSION
from ...entities.types import EntityType
from ...providers.results import RelationshipTargetType
from ...reasoning import Finding, FindingCategory, InvestigationSummary, Severity
from ..engine import compute_artifact_id
from ..models import (
    DetectionArtifact,
    DetectionReference,
    DetectionTarget,
    DetectionTemplate,
    DetectionValidation,
)
from ..registry import DetectionGenerator
from ..templates import TemplateRegistry
from ..types import (
    DetectionCapability,
    DetectionCategory,
    DetectionLanguage,
    DetectionSeverity,
)

_AUTHOR = "ThreatLens Detection Engine"
_SOURCE = "Generated from InvestigationSummary"
_DEFAULT_REFERENCE = "https://github.com/Otomen1/ThreatLens"
_ATTACK_URL = "https://attack.mitre.org/techniques/{path}/"
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_TEMPLATE_ID = "yara-file-hash"

# subject type → (hex length, YARA hash function)
_HASH_SPEC: dict[EntityType, tuple[int, str]] = {
    EntityType.MD5: (32, "md5"),
    EntityType.SHA1: (40, "sha1"),
    EntityType.SHA256: (64, "sha256"),
}

_LEVEL_BY_SEVERITY = {
    DetectionSeverity.CRITICAL: "critical",
    DetectionSeverity.HIGH: "high",
    DetectionSeverity.MEDIUM: "medium",
    DetectionSeverity.LOW: "low",
    DetectionSeverity.INFORMATIONAL: "informational",
}

_CAPABILITIES = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.HASH_SIGNATURE})


def _build_templates() -> TemplateRegistry:
    """One reusable, pure YARA template (file/hash)."""
    registry = TemplateRegistry()
    registry.register(
        DetectionTemplate(
            id=_TEMPLATE_ID,
            name=_TEMPLATE_ID,
            language=DetectionLanguage.YARA,
            target=DetectionTarget(language=DetectionLanguage.YARA, platform="generic"),
            category=DetectionCategory.FILE,
            description="YARA file-hash template (hash module).",
            capabilities=_CAPABILITIES,
        )
    )
    return registry


_TEMPLATES = _build_templates()


class YaraGenerator(DetectionGenerator):
    """Generates deterministic hash-based YARA rules from file-hash findings."""

    @property
    def name(self) -> str:
        return "yara"

    @property
    def language(self) -> DetectionLanguage:
        return DetectionLanguage.YARA

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return _CAPABILITIES

    @property
    def priority(self) -> int:
        return 20

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        """One YARA rule per eligible file hash (findings on a hash are merged)."""
        groups: dict[tuple[str, str], list[Finding]] = {}
        for finding in summary.findings:
            info = _eligible(finding)
            if info is None:
                continue
            groups.setdefault(info, []).append(finding)

        artifacts: list[DetectionArtifact] = []
        for key in sorted(groups):
            artifacts.append(_build_artifact(key[0], key[1], groups[key], summary.generated_at))
        return artifacts


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #


def _eligible(finding: Finding) -> tuple[str, str] | None:
    """Return ``(hash_func, hash_value)`` for a valid file-hash finding, else None."""
    spec = _HASH_SPEC.get(finding.subject_type)
    if spec is None:
        return None
    if finding.severity <= Severity.INFORMATIONAL:
        return None
    if finding.categories == frozenset({FindingCategory.INFORMATIONAL}):
        return None
    length, func = spec
    value = finding.subject_value.strip().lower()
    if len(value) != length or not _HEX_RE.match(value):
        return None  # insufficient/invalid — no rule beats a weak rule
    return func, value


# --------------------------------------------------------------------------- #
# Rule construction
# --------------------------------------------------------------------------- #


def _build_artifact(
    hash_func: str,
    hash_value: str,
    findings: list[Finding],
    generated_at: datetime,
) -> DetectionArtifact:
    template = _TEMPLATES.get(_TEMPLATE_ID)
    assert template is not None  # registered above

    finding_ids = sorted({f.id for f in findings})
    sources = sorted({s for f in findings for s in f.sources})
    techniques = _techniques(findings)
    severity = DetectionSeverity(int(max(f.severity for f in findings)))
    level = _LEVEL_BY_SEVERITY[severity]

    digest = hashlib.sha256(f"{hash_func}:{hash_value}".encode()).hexdigest()
    rule_name = f"ThreatLens_Malware_{digest[:12]}"
    rule_id = f"yar_{digest[:16]}"
    reference = (
        _ATTACK_URL.format(path=_attack_path(techniques[0])) if techniques else _DEFAULT_REFERENCE
    )
    description = _description(finding_ids, sources)

    # Identity hashes the rule minus the volatile date (see module docstring).
    canonical = _render_rule(
        rule_name=rule_name,
        hash_func=hash_func,
        hash_value=hash_value,
        description=description,
        date=None,
        reference=reference,
        finding_ids=finding_ids,
        rule_id=rule_id,
        detection_id="",
        level=level,
        techniques=techniques,
    )
    artifact_id = compute_artifact_id(
        language=DetectionLanguage.YARA,
        target_platform=template.target.platform,
        category=template.category,
        content=canonical,
        rule_id=rule_id,
        source_finding_ids=finding_ids,
    )
    content = _render_rule(
        rule_name=rule_name,
        hash_func=hash_func,
        hash_value=hash_value,
        description=description,
        date=generated_at.strftime("%Y-%m-%d"),
        reference=reference,
        finding_ids=finding_ids,
        rule_id=rule_id,
        detection_id=artifact_id,
        level=level,
        techniques=techniques,
    )

    references = [
        DetectionReference(title=f"MITRE ATT&CK {t}", url=_ATTACK_URL.format(path=_attack_path(t)))
        for t in techniques
    ]
    references += [DetectionReference(title=f"ThreatLens finding {fid}") for fid in finding_ids]

    metadata = {
        "finding_ids": ",".join(finding_ids),
        "rule_id": rule_id,
        "detection_id": artifact_id,
        "hash_type": hash_func,
        "hash": hash_value,
        "source": _SOURCE,
    }
    if sources:
        metadata["sources"] = ",".join(sources)
    if techniques:
        metadata["attack"] = ",".join(techniques)

    return DetectionArtifact(
        id=artifact_id,
        language=DetectionLanguage.YARA,
        target=template.target,
        title=f"Malicious file ({hash_func.upper()}): {hash_value}",
        description=description,
        content=content,
        severity=severity,
        category=template.category,
        capabilities=template.capabilities,
        source_finding_ids=tuple(finding_ids),
        references=tuple(references),
        validation=DetectionValidation(),
        rule_id=rule_id,
        metadata=metadata,
    )


def _description(finding_ids: list[str], sources: list[str]) -> str:
    text = (
        "Detects a file matching a hash flagged as malicious by ThreatLens "
        f"finding(s) {', '.join(finding_ids)}"
    )
    if sources:
        text += f" via {', '.join(sources)}"
    return text + "."


def _techniques(findings: Iterable[Finding]) -> list[str]:
    found: set[str] = set()
    for finding in findings:
        for rel in finding.relationships:
            relationship = rel.relationship
            if relationship.target_type is RelationshipTargetType.ATTACK_PATTERN:
                value = relationship.target_value.strip().upper()
                if _TECHNIQUE_RE.match(value):
                    found.add(value)
    return sorted(found)


def _attack_path(technique: str) -> str:
    base, _, sub = technique.partition(".")
    return f"{base}/{sub}" if sub else base


# --------------------------------------------------------------------------- #
# Deterministic YARA rendering (hand-rolled — no yara dependency)
# --------------------------------------------------------------------------- #


def _render_rule(
    *,
    rule_name: str,
    hash_func: str,
    hash_value: str,
    description: str,
    date: str | None,
    reference: str,
    finding_ids: list[str],
    rule_id: str,
    detection_id: str,
    level: str,
    techniques: list[str],
) -> str:
    meta = [
        f"        description = {_s(description)}",
        f"        author = {_s(_AUTHOR)}",
    ]
    if date is not None:
        meta.append(f"        date = {_s(date)}")
    meta.append(f"        reference = {_s(reference)}")
    meta.append(f"        finding_ids = {_s(','.join(finding_ids))}")
    meta.append(f"        rule_id = {_s(rule_id)}")
    if detection_id:
        meta.append(f"        detection_id = {_s(detection_id)}")
    meta.append(f"        source = {_s(_SOURCE)}")
    meta.append(f"        threatlens_version = {_s(THREATLENS_VERSION)}")
    meta.append(f"        severity = {_s(level)}")
    meta.append(f"        hash_type = {_s(hash_func)}")
    meta.append(f"        hash = {_s(hash_value)}")
    if techniques:
        meta.append(f"        mitre_attack = {_s(','.join(techniques))}")

    lines = [
        'import "hash"',
        "",
        f"rule {rule_name}",
        "{",
        "    meta:",
        *meta,
        "    condition:",
        f"        filesize < 100MB and hash.{hash_func}(0, filesize) == {_s(hash_value)}",
        "}",
    ]
    return "\n".join(lines) + "\n"


def _s(scalar: str) -> str:
    """A double-quoted YARA string (backslashes and quotes escaped)."""
    return '"' + scalar.replace("\\", "\\\\").replace('"', '\\"') + '"'
