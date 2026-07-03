"""Shared, pure helpers for the SIEM detection generators (Phase 4.4).

New code for Phase 4.4 — not a change to the frozen framework. The five SIEM
generators (Splunk SPL, Sentinel KQL, Elastic ES|QL, Chronicle YARA-L, QRadar
AQL) consume only ``Finding`` objects and share observable classification,
deterministic id allocation, value escaping, a provenance-metadata builder,
parser-level validation, and artifact construction; each renders its own
platform-native query on top (never Sigma converted).

Determinism: identifiers hash only stable values (platform, IOC kind, value) —
never the ``generated_at`` timestamp or the detection id. The query body is the
identity; the ``generated_at`` timestamp (from the summary, never the wall clock)
and the detection id appear only in the provenance metadata, which is excluded
from the identity hash.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from re import compile as _re

from ... import __version__ as PLATFORM_VERSION
from ...entities.types import EntityType
from ...providers.results import RelationshipTargetType
from ...reasoning import Finding, FindingCategory, Severity
from ..engine import compute_artifact_id
from ..models import (
    DetectionArtifact,
    DetectionReference,
    DetectionTemplate,
    DetectionValidation,
)
from ..types import (
    DetectionCategory,
    DetectionLanguage,
    DetectionSeverity,
    DetectionValidationStatus,
)

SOURCE = "Generated from InvestigationSummary"
_DEFAULT_REFERENCE = "https://github.com/Otomen1/ThreatLens"
_ATTACK_URL = "https://attack.mitre.org/techniques/{path}/"
_TECHNIQUE_RE = _re(r"^T\d{4}(?:\.\d{3})?$")
_HEX_RE = _re(r"^[0-9a-f]+$")

_HASH_LEN = {EntityType.MD5: 32, EntityType.SHA1: 40, EntityType.SHA256: 64}
_LABELS = {
    "ip": "IP address",
    "domain": "domain",
    "url": "URL",
    "hash": "file hash",
    "process": "process",
    "registry": "registry key",
    "powershell": "PowerShell command",
}
CATEGORY_BY_KIND = {
    "ip": DetectionCategory.NETWORK,
    "domain": DetectionCategory.DNS,
    "url": DetectionCategory.HTTP,
    "hash": DetectionCategory.FILE,
    "process": DetectionCategory.PROCESS,
    "registry": DetectionCategory.REGISTRY,
    "powershell": DetectionCategory.PROCESS,
}
_LEVEL = {
    DetectionSeverity.CRITICAL: "critical",
    DetectionSeverity.HIGH: "high",
    DetectionSeverity.MEDIUM: "medium",
    DetectionSeverity.LOW: "low",
    DetectionSeverity.INFORMATIONAL: "informational",
}


@dataclass(frozen=True)
class Observable:
    """A queryable indicator distilled from a finding's subject."""

    kind: str  # ip|domain|url|hash|process|registry|powershell
    value: str
    subtype: str  # e.g. "ipv4", "md5", "process_name"


@dataclass(frozen=True)
class SiemData:
    """The platform-agnostic facts a SIEM query is built from."""

    observable: Observable
    finding_ids: tuple[str, ...]
    sources: tuple[str, ...]
    techniques: tuple[str, ...]
    severity: DetectionSeverity
    level: str
    confidence_score: int
    confidence_band: str
    generator: str
    platform: str


# --------------------------------------------------------------------------- #
# Eligibility / grouping
# --------------------------------------------------------------------------- #


def classify(finding: Finding) -> Observable | None:
    """Distil a finding into a queryable observable, or ``None`` if unsupported."""
    subject = finding.subject_type
    if finding.severity <= Severity.INFORMATIONAL:
        return None
    if finding.categories == frozenset({FindingCategory.INFORMATIONAL}):
        return None
    value = finding.subject_value.strip()
    if not value:
        return None
    if subject in (EntityType.IPV4, EntityType.IPV6):
        return Observable("ip", value, subject.value)
    if subject is EntityType.DOMAIN:
        return Observable("domain", value.lower(), "domain")
    if subject is EntityType.URL:
        return Observable("url", value, "url")
    if subject in _HASH_LEN:
        hexed = value.lower()
        if len(hexed) != _HASH_LEN[subject] or not _HEX_RE.match(hexed):
            return None
        return Observable("hash", hexed, subject.value)
    if subject is EntityType.PROCESS_NAME:
        return Observable("process", value, "process_name")
    if subject is EntityType.REGISTRY_KEY:
        return Observable("registry", value, "registry_key")
    if subject is EntityType.POWERSHELL_COMMAND:
        return Observable("powershell", value, "powershell_command")
    return None


def group_eligible(findings: Iterable[Finding]) -> dict[Observable, list[Finding]]:
    groups: dict[Observable, list[Finding]] = {}
    for finding in findings:
        observable = classify(finding)
        if observable is not None:
            groups.setdefault(observable, []).append(finding)
    return groups


def collect(
    observable: Observable, findings: list[Finding], generator: str, platform: str
) -> SiemData:
    finding_ids = tuple(sorted({f.id for f in findings}))
    sources = tuple(sorted({s for f in findings for s in f.sources}))
    techniques = tuple(_techniques(findings))
    severity = DetectionSeverity(int(max(f.severity for f in findings)))
    lead = max(findings, key=lambda f: f.confidence.score)
    return SiemData(
        observable=observable,
        finding_ids=finding_ids,
        sources=sources,
        techniques=techniques,
        severity=severity,
        level=_LEVEL[severity],
        confidence_score=lead.confidence.score,
        confidence_band=lead.confidence.band.value,
        generator=generator,
        platform=platform,
    )


# --------------------------------------------------------------------------- #
# Deterministic identity & escaping
# --------------------------------------------------------------------------- #


def rule_id_for(prefix: str, kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{prefix}|{kind}|{value.lower()}".encode()).hexdigest()
    return f"{prefix}_{digest[:16]}"


def rule_slug(prefix: str, kind: str, value: str) -> str:
    """A YARA-L-safe rule identifier (letters/digits/underscore only)."""
    digest = hashlib.sha256(f"{prefix}|{kind}|{value.lower()}".encode()).hexdigest()
    return f"threatlens_{prefix}_{digest[:12]}"


def dq(value: str) -> str:
    """Escape a double-quoted string (SPL/KQL/ES|QL/YARA-L)."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def aql(value: str) -> str:
    """Escape a single-quoted AQL string (double the quotes)."""
    return value.replace("'", "''")


# --------------------------------------------------------------------------- #
# Provenance metadata (shared by the comment-header languages)
# --------------------------------------------------------------------------- #


def meta_lines(data: SiemData, rule_id: str, detection_id: str, generated_at: str) -> list[str]:
    """Provenance lines; ``detection_id``/``generated_at`` omitted when empty."""
    lines = [
        "ThreatLens Detection",
        f"generator: {data.generator}",
        f"platform: {data.platform}",
        f"rule_id: {rule_id}",
    ]
    if detection_id:
        lines.append(f"detection_id: {detection_id}")
    lines.append(f"finding_ids: {','.join(data.finding_ids)}")
    lines.append(f"severity: {data.level}")
    lines.append(f"confidence: {data.confidence_score} ({data.confidence_band})")
    lines.append(f"mitre: {','.join(data.techniques) if data.techniques else 'n/a'}")
    lines.append(f"ioc: {data.observable.kind}={data.observable.value}")
    if generated_at:
        lines.append(f"generated_at: {generated_at}")
    lines.append(f"engine_version: {PLATFORM_VERSION}")
    return lines


def comment_header(
    data: SiemData, rule_id: str, detection_id: str, generated_at: str, prefix: str
) -> str:
    """Provenance rendered as ``prefix``-led comment lines (e.g. ``"// "``)."""
    lines = meta_lines(data, rule_id, detection_id, generated_at)
    return "\n".join(f"{prefix}{line}" for line in lines)


# --------------------------------------------------------------------------- #
# Parser-level validation (no native validators available)
# --------------------------------------------------------------------------- #

_REQUIRED_TOKENS = {
    DetectionLanguage.SPLUNK_SPL: ("index=",),
    DetectionLanguage.SENTINEL_KQL: ("| where",),
    DetectionLanguage.ELASTIC_ESQL: ("FROM ", "WHERE "),
    DetectionLanguage.CHRONICLE_YARA_L: ("rule ", "events:", "condition:"),
    DetectionLanguage.QRADAR_AQL: ("SELECT ", "FROM "),
}


def parser_validate(language: DetectionLanguage, content: str) -> DetectionValidation:
    """Lightweight structural validation (native validators are unavailable)."""
    tokens = _REQUIRED_TOKENS.get(language, ())
    problems = [f"missing '{tok.strip()}'" for tok in tokens if tok not in content]
    if language is DetectionLanguage.CHRONICLE_YARA_L and not _braces_balanced(content):
        problems.append("unbalanced braces")
    if problems:
        return DetectionValidation(
            status=DetectionValidationStatus.INVALID,
            validator="threatlens-parser",
            messages=tuple(problems),
        )
    return DetectionValidation(
        status=DetectionValidationStatus.VALID, validator="threatlens-parser"
    )


def _braces_balanced(content: str) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for char in content:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not in_string


# --------------------------------------------------------------------------- #
# Artifact construction (shared; each generator passes its own renderer)
# --------------------------------------------------------------------------- #

# (data, rule_id, detection_id, generated_at) -> query text.
Renderer = Callable[[SiemData, str, str, str], str]


def build_artifact(
    *,
    language: DetectionLanguage,
    generator: str,
    platform: str,
    id_prefix: str,
    template: DetectionTemplate,
    observable: Observable,
    findings: list[Finding],
    generated_at_iso: str,
    render: Renderer,
) -> DetectionArtifact:
    data = collect(observable, findings, generator, platform)
    category = CATEGORY_BY_KIND[observable.kind]
    rule_id = rule_id_for(id_prefix, observable.kind, observable.value)

    canonical = render(data, rule_id, "", "")  # no detection_id, no timestamp
    artifact_id = compute_artifact_id(
        language=language,
        target_platform=template.target.platform,
        category=category,
        content=canonical,
        rule_id=rule_id,
        source_finding_ids=list(data.finding_ids),
    )
    content = render(data, rule_id, artifact_id, generated_at_iso)

    refs = [
        DetectionReference(title=f"MITRE ATT&CK {t}", url=_ATTACK_URL.format(path=_attack_path(t)))
        for t in data.techniques
    ]
    refs += [DetectionReference(title=f"ThreatLens finding {fid}") for fid in data.finding_ids]

    metadata = {
        "detection_id": artifact_id,
        "generator": generator,
        "platform": platform,
        "finding_ids": ",".join(data.finding_ids),
        "severity": data.level,
        "confidence": str(data.confidence_score),
        "confidence_band": data.confidence_band,
        "ioc_type": observable.kind,
        "ioc_value": observable.value,
        "generated_at": generated_at_iso,
        "engine_version": PLATFORM_VERSION,
        "rule_id": rule_id,
        "source": SOURCE,
    }
    if data.techniques:
        metadata["mitre"] = ",".join(data.techniques)
    if data.sources:
        metadata["sources"] = ",".join(data.sources)

    return DetectionArtifact(
        id=artifact_id,
        language=language,
        target=template.target,
        title=f"Malicious {_LABELS[observable.kind]}: {observable.value}",
        description=(
            f"{platform} detection for {observable.kind} {observable.value}, "
            f"from ThreatLens finding(s) {', '.join(data.finding_ids)}."
        ),
        content=content,
        severity=data.severity,
        category=category,
        capabilities=template.capabilities,
        source_finding_ids=data.finding_ids,
        references=tuple(refs),
        validation=parser_validate(language, content),
        rule_id=rule_id,
        metadata=metadata,
    )


def label(kind: str) -> str:
    return _LABELS[kind]


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
