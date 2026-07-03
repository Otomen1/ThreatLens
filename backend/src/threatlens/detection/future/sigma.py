"""Sigma detection generator — the first concrete generator (Phase 4.1).

A pure, deterministic :class:`~threatlens.detection.registry.DetectionGenerator`
that converts an ``InvestigationSummary``'s findings into minimal, readable Sigma
rules. It consumes **only** ``Finding`` objects — never provider responses, raw
TI, reputation scores, WHOIS, NVD/MITRE JSON, or any API payload. No AI, no
network, no wall clock.

Scope (deliberately concrete, never speculative):

* Sigma is emitted only for findings whose subject is a **log-observable IOC** —
  IPv4/IPv6, domain, URL, or file hash (MD5/SHA1/SHA256) — and whose disposition
  is actionable (severity above informational). CWE, CAPEC, CVE, ATT&CK
  techniques, malware families, threat actors, and informational findings do not
  yield a standalone rule (their ATT&CK context enriches IOC rules' tags and
  references). See the Phase 4.1 architecture doc for the mapping philosophy.

Identity: the Sigma rule ``id`` (a UUIDv5) and the framework artifact id hash only
**stable** values — subject, log source, and provenance — never the ``date`` and
never a timestamp, so re-generating the same detection yields the same ids. The
human-readable ``date`` field carries the investigation date but is intentionally
excluded from identity.

Validation stays ``UNVALIDATED`` — Sigma syntax validation arrives in a later
phase.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

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

# A fixed namespace so Sigma rule UUIDs are deterministic (uuid5, never random).
_NAMESPACE = uuid.UUID("6f0d9c2a-7d1b-5e6a-9f2c-2a1b3c4d5e6f")
_AUTHOR = "ThreatLens Detection Engine"
_STATUS = "experimental"
_BASE_TAG = "threatlens.detection"
_ATTACK_URL = "https://attack.mitre.org/techniques/{path}/"
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_LEVEL_BY_SEVERITY = {
    DetectionSeverity.CRITICAL: "critical",
    DetectionSeverity.HIGH: "high",
    DetectionSeverity.MEDIUM: "medium",
    DetectionSeverity.LOW: "low",
    DetectionSeverity.INFORMATIONAL: "informational",
}


@dataclass(frozen=True)
class _Spec:
    """The Sigma shape for one IOC subject kind (pure data)."""

    template_id: str
    logsource: tuple[tuple[str, str], ...]
    field: str
    kind_label: str
    activity: str
    falsepositive: str


# Subject-type → Sigma mapping. Minimal, standard log sources/fields; no
# vendor-specific optimization.
_SPECS: dict[EntityType, _Spec] = {
    EntityType.IPV4: _Spec(
        "sigma-network-ip",
        (("category", "firewall"),),
        "dst_ip",
        "IP address",
        "network connections to",
        "Legitimate traffic to this destination",
    ),
    EntityType.IPV6: _Spec(
        "sigma-network-ip",
        (("category", "firewall"),),
        "dst_ip",
        "IP address",
        "network connections to",
        "Legitimate traffic to this destination",
    ),
    EntityType.DOMAIN: _Spec(
        "sigma-dns-domain",
        (("category", "dns"),),
        "query",
        "domain",
        "DNS resolution of",
        "Legitimate use of this domain",
    ),
    EntityType.URL: _Spec(
        "sigma-proxy-url",
        (("category", "proxy"),),
        "c-uri|contains",
        "URL",
        "web requests to",
        "Legitimate access to this URL",
    ),
    EntityType.MD5: _Spec(
        "sigma-file-hash",
        (("category", "process_creation"), ("product", "windows")),
        "Hashes|contains",
        "file hash",
        "execution of a file with hash",
        "Legitimate software sharing this hash",
    ),
    EntityType.SHA1: _Spec(
        "sigma-file-hash",
        (("category", "process_creation"), ("product", "windows")),
        "Hashes|contains",
        "file hash",
        "execution of a file with hash",
        "Legitimate software sharing this hash",
    ),
    EntityType.SHA256: _Spec(
        "sigma-file-hash",
        (("category", "process_creation"), ("product", "windows")),
        "Hashes|contains",
        "file hash",
        "execution of a file with hash",
        "Legitimate software sharing this hash",
    ),
}

_NETWORK_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.NETWORK_SIGNATURE})
_HASH_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.HASH_SIGNATURE})
_CAPABILITIES_BY_TEMPLATE = {
    "sigma-network-ip": _NETWORK_CAPS,
    "sigma-dns-domain": _NETWORK_CAPS,
    "sigma-proxy-url": _NETWORK_CAPS,
    "sigma-file-hash": _HASH_CAPS,
}

_CATEGORY_BY_TEMPLATE = {
    "sigma-network-ip": DetectionCategory.NETWORK,
    "sigma-dns-domain": DetectionCategory.DNS,
    "sigma-proxy-url": DetectionCategory.HTTP,
    "sigma-file-hash": DetectionCategory.FILE,
}


def _build_templates() -> TemplateRegistry:
    """Register one pure Sigma template per IOC subject kind."""
    registry = TemplateRegistry()
    for template_id, category in _CATEGORY_BY_TEMPLATE.items():
        registry.register(
            DetectionTemplate(
                id=template_id,
                name=template_id,
                language=DetectionLanguage.SIGMA,
                target=DetectionTarget(language=DetectionLanguage.SIGMA, platform="generic"),
                category=category,
                description=f"Sigma IOC template ({category.value}).",
                capabilities=_CAPABILITIES_BY_TEMPLATE[template_id],
            )
        )
    return registry


_TEMPLATES = _build_templates()


class SigmaGenerator(DetectionGenerator):
    """Generates minimal, deterministic Sigma rules from IOC findings."""

    @property
    def name(self) -> str:
        return "sigma"

    @property
    def language(self) -> DetectionLanguage:
        return DetectionLanguage.SIGMA

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.NETWORK_SIGNATURE})

    @property
    def priority(self) -> int:
        return 10

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        """One Sigma rule per eligible IOC (findings on the same IOC are merged)."""
        groups: dict[tuple[EntityType, str], list[Finding]] = {}
        for finding in summary.findings:
            if not _eligible(finding):
                continue
            key = (finding.subject_type, finding.subject_value.strip().lower())
            groups.setdefault(key, []).append(finding)

        artifacts: list[DetectionArtifact] = []
        for key in sorted(groups, key=lambda k: (k[0].value, k[1])):
            artifact = _build_artifact(key[0], groups[key], summary.generated_at)
            if artifact is not None:
                artifacts.append(artifact)
        return artifacts


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #


def _eligible(finding: Finding) -> bool:
    """True for actionable, log-observable IOC findings (never speculative)."""
    if finding.subject_type not in _SPECS:
        return False
    if finding.severity <= Severity.INFORMATIONAL:
        return False
    if finding.categories == frozenset({FindingCategory.INFORMATIONAL}):
        return False
    return bool(finding.subject_value.strip())


# --------------------------------------------------------------------------- #
# Rule construction
# --------------------------------------------------------------------------- #


def _build_artifact(
    subject_type: EntityType,
    findings: list[Finding],
    generated_at: datetime,
) -> DetectionArtifact | None:
    spec = _SPECS[subject_type]
    template = _TEMPLATES.get(spec.template_id)
    if template is None:  # pragma: no cover - templates are registered above
        return None

    subject_value = sorted({f.subject_value for f in findings})[0]
    finding_ids = sorted({f.id for f in findings})
    sources = sorted({s for f in findings for s in f.sources})
    techniques = _techniques(findings)
    severity = DetectionSeverity(int(max(f.severity for f in findings)))
    level = _LEVEL_BY_SEVERITY[severity]

    identity = f"{subject_type.value}|{subject_value.lower()}|{spec.field}"
    rule_id = str(uuid.uuid5(_NAMESPACE, identity))
    title = f"Malicious {spec.kind_label}: {subject_value}"
    description = _description(spec, subject_value, finding_ids, sources)
    tags = [_BASE_TAG, *(f"attack.{t.lower()}" for t in techniques)]
    yaml_refs = [_ATTACK_URL.format(path=_attack_path(t)) for t in techniques]
    yaml_refs += [f"ThreatLens finding: {fid}" for fid in finding_ids]

    canonical = _render_rule(
        title=title,
        rule_id=rule_id,
        description=description,
        references=yaml_refs,
        date=None,
        tags=tags,
        logsource=spec.logsource,
        field=spec.field,
        value=subject_value,
        falsepositives=[spec.falsepositive],
        level=level,
    )
    content = _render_rule(
        title=title,
        rule_id=rule_id,
        description=description,
        references=yaml_refs,
        date=generated_at.strftime("%Y-%m-%d"),
        tags=tags,
        logsource=spec.logsource,
        field=spec.field,
        value=subject_value,
        falsepositives=[spec.falsepositive],
        level=level,
    )

    artifact_id = compute_artifact_id(
        language=DetectionLanguage.SIGMA,
        target_platform=template.target.platform,
        category=template.category,
        content=canonical,  # date-free → identity is timestamp-independent
        rule_id=rule_id,
        source_finding_ids=finding_ids,
    )

    references = [
        DetectionReference(title=f"MITRE ATT&CK {t}", url=_ATTACK_URL.format(path=_attack_path(t)))
        for t in techniques
    ]
    references += [DetectionReference(title=f"ThreatLens finding {fid}") for fid in finding_ids]

    metadata = {
        "finding_ids": ",".join(finding_ids),
        "detection_id": artifact_id,
        "rule_id": rule_id,
        "subject": subject_value,
        "subject_type": subject_type.value,
        "sigma_id": rule_id,
    }
    if sources:
        metadata["sources"] = ",".join(sources)
    if techniques:
        metadata["attack"] = ",".join(techniques)

    return DetectionArtifact(
        id=artifact_id,
        language=DetectionLanguage.SIGMA,
        target=template.target,
        title=title,
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


def _description(
    spec: _Spec, subject_value: str, finding_ids: list[str], sources: list[str]
) -> str:
    text = (
        f"Detects {spec.activity} {subject_value}, flagged as malicious by ThreatLens "
        f"finding(s) {', '.join(finding_ids)}"
    )
    if sources:
        text += f" via {', '.join(sources)}"
    return text + "."


def _techniques(findings: Iterable[Finding]) -> list[str]:
    """ATT&CK technique ids cited by the findings' relationships (stable, sorted)."""
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
    """T1059 → 'T1059'; T1059.001 → 'T1059/001' (MITRE URL path)."""
    base, _, sub = technique.partition(".")
    return f"{base}/{sub}" if sub else base


# --------------------------------------------------------------------------- #
# Deterministic YAML rendering (hand-rolled — no yaml dependency)
# --------------------------------------------------------------------------- #


def _render_rule(
    *,
    title: str,
    rule_id: str,
    description: str,
    references: list[str],
    date: str | None,
    tags: list[str],
    logsource: tuple[tuple[str, str], ...],
    field: str,
    value: str,
    falsepositives: list[str],
    level: str,
) -> str:
    lines = [
        f"title: {_q(title)}",
        f"id: {rule_id}",
        f"status: {_STATUS}",
        f"description: {_q(description)}",
        f"author: {_q(_AUTHOR)}",
        "references:",
        *(f"    - {_q(ref)}" for ref in references),
    ]
    if date is not None:
        lines.append(f"date: {date}")
    lines.append("tags:")
    lines.extend(f"    - {tag}" for tag in tags)
    lines.append("logsource:")
    lines.extend(f"    {key}: {val}" for key, val in logsource)
    lines.append("detection:")
    lines.append("    selection:")
    lines.append(f"        {field}: {_q(value)}")
    lines.append("    condition: selection")
    lines.append("falsepositives:")
    lines.extend(f"    - {_q(fp)}" for fp in falsepositives)
    lines.append(f"level: {level}")
    return "\n".join(lines) + "\n"


def _q(scalar: str) -> str:
    """A single-quoted YAML scalar (single quotes doubled per the YAML spec)."""
    return "'" + scalar.replace("'", "''") + "'"
