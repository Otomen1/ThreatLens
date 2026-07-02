"""Shared, pure helpers for the network detection generators (Suricata + Snort).

New code for Phase 4.3 — not a change to the frozen framework. Both network
generators consume only ``Finding`` objects and share eligibility, deterministic
SID/rule-id allocation, content encoding, ATT&CK extraction, and artifact
construction; each renders its own engine-specific rule syntax on top.

Nothing here performs I/O, calls AI, reads the wall clock, or mutates a summary.

SID allocation (deterministic, no randomness, timestamp-independent): a rule's
Suricata/Snort ``sid`` is ``1_000_000 + (sha256(engine|kind|value) mod 9_000_000)``
— stable per IOC per engine, in the custom/local SID range. The engine is part of
the hash so the same IOC gets distinct Suricata and Snort SIDs.
"""

from __future__ import annotations

import hashlib
import string
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from re import compile as _re
from urllib.parse import urlsplit

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
from ..types import DetectionCategory, DetectionLanguage, DetectionSeverity

CLASSTYPE = "trojan-activity"
SOURCE = "Generated from InvestigationSummary"
_DEFAULT_REFERENCE = "github.com/Otomen1/ThreatLens"
_ATTACK_URL = "attack.mitre.org/techniques/{path}/"
_TECHNIQUE_RE = _re(r"^T\d{4}(?:\.\d{3})?$")

_SID_BASE = 1_000_000
_SID_RANGE = 9_000_000

_SUPPORTED = frozenset({EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN, EntityType.URL})
_LABELS = {"ip": "IP address", "domain": "domain", "url": "URL"}
CATEGORY_BY_KIND = {
    "ip": DetectionCategory.NETWORK,
    "domain": DetectionCategory.DNS,
    "url": DetectionCategory.HTTP,
}
_PRIORITY_BY_SEVERITY = {
    DetectionSeverity.CRITICAL: 1,
    DetectionSeverity.HIGH: 1,
    DetectionSeverity.MEDIUM: 2,
    DetectionSeverity.LOW: 3,
    DetectionSeverity.INFORMATIONAL: 4,
}
# Bytes rendered literally in a content string; everything else becomes |HH|.
_SAFE = set(string.ascii_letters + string.digits + "._-/")


@dataclass(frozen=True)
class NetRuleData:
    """The engine-agnostic facts a network rule is built from."""

    kind: str  # "ip" | "domain" | "url"
    value: str
    finding_ids: tuple[str, ...]
    sources: tuple[str, ...]
    techniques: tuple[str, ...]
    severity: DetectionSeverity
    priority: int


# --------------------------------------------------------------------------- #
# Eligibility / grouping
# --------------------------------------------------------------------------- #


def eligible(finding: Finding) -> tuple[str, str] | None:
    """Return ``(kind, value)`` for a network-observable finding, else ``None``."""
    subject = finding.subject_type
    if subject not in _SUPPORTED:
        return None
    if finding.severity <= Severity.INFORMATIONAL:
        return None
    if finding.categories == frozenset({FindingCategory.INFORMATIONAL}):
        return None
    value = finding.subject_value.strip()
    if not value:
        return None
    if subject in (EntityType.IPV4, EntityType.IPV6):
        return "ip", value
    if subject is EntityType.DOMAIN:
        return "domain", value.lower()
    return "url", value


def group_eligible(findings: Iterable[Finding]) -> dict[tuple[str, str], list[Finding]]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        key = eligible(finding)
        if key is not None:
            groups.setdefault(key, []).append(finding)
    return groups


def collect(kind: str, value: str, findings: list[Finding]) -> NetRuleData:
    finding_ids = tuple(sorted({f.id for f in findings}))
    sources = tuple(sorted({s for f in findings for s in f.sources}))
    techniques = tuple(_techniques(findings))
    severity = DetectionSeverity(int(max(f.severity for f in findings)))
    return NetRuleData(
        kind=kind,
        value=value,
        finding_ids=finding_ids,
        sources=sources,
        techniques=techniques,
        severity=severity,
        priority=_PRIORITY_BY_SEVERITY[severity],
    )


# --------------------------------------------------------------------------- #
# Deterministic identity
# --------------------------------------------------------------------------- #


def _digest(engine: str, kind: str, value: str) -> str:
    return hashlib.sha256(f"{engine}|{kind}|{value.lower()}".encode()).hexdigest()


def sid_for(engine: str, kind: str, value: str) -> int:
    return _SID_BASE + (int(_digest(engine, kind, value)[:12], 16) % _SID_RANGE)


def rule_id_for(prefix: str, engine: str, kind: str, value: str) -> str:
    return f"{prefix}_{_digest(engine, kind, value)[:16]}"


# --------------------------------------------------------------------------- #
# Rendering helpers (shared by both engines)
# --------------------------------------------------------------------------- #


def content_encode(raw: str) -> str:
    """Encode a string for a ``content:"..."`` value (non-safe bytes → ``|HH|``)."""
    out: list[str] = []
    run: list[str] = []
    for byte in raw.encode("utf-8"):
        if chr(byte) in _SAFE:
            if run:
                out.append("|" + " ".join(run) + "|")
                run = []
            out.append(chr(byte))
        else:
            run.append(f"{byte:02X}")
    if run:
        out.append("|" + " ".join(run) + "|")
    return "".join(out)


def msg_escape(text: str) -> str:
    """Escape a Suricata/Snort ``msg`` value (backslash, quote, semicolon)."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")


def references(techniques: Iterable[str]) -> list[str]:
    """``reference:url,<value>`` values: MITRE techniques plus a ThreatLens link."""
    refs = [_ATTACK_URL.format(path=_attack_path(t)) for t in techniques]
    refs.append(_DEFAULT_REFERENCE)
    return refs


def metadata_option(data: NetRuleData, rule_id: str, detection_id: str) -> str:
    """A single ``metadata:`` option carrying full provenance (single-token values)."""
    entries = [f"threatlens_version {PLATFORM_VERSION}", f"rule_id {rule_id}"]
    if detection_id:
        entries.append(f"detection_id {detection_id}")
    entries.append("created_from investigation_summary")
    entries += [f"finding_id {fid}" for fid in data.finding_ids]
    entries += [f"source {s}" for s in data.sources]
    entries += [f"mitre_attack {t}" for t in data.techniques]
    return "metadata:" + ", ".join(entries)


def url_parts(url: str) -> tuple[str, str] | None:
    """Split a URL into ``(host, path+query)``; ``None`` if it has no host."""
    try:
        parsed = urlsplit(url if "://" in url else f"http://{url}")
    except ValueError:
        return None
    host = parsed.hostname
    if not host:
        return None
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, path


def label(kind: str) -> str:
    return _LABELS[kind]


# --------------------------------------------------------------------------- #
# Artifact construction (shared; each engine passes its own renderer)
# --------------------------------------------------------------------------- #

# A renderer turns (data, sid, rule_id, detection_id) into a rule string, or
# ``None`` when the finding cannot yield a deterministic rule (e.g. a bad URL).
Renderer = Callable[[NetRuleData, int, str, str], "str | None"]


def build_artifact(
    *,
    language: DetectionLanguage,
    engine: str,
    id_prefix: str,
    template: DetectionTemplate,
    kind: str,
    value: str,
    findings: list[Finding],
    render: Renderer,
) -> DetectionArtifact | None:
    """Build one network DetectionArtifact (identity excludes the detection_id)."""
    data = collect(kind, value, findings)
    sid = sid_for(engine, kind, value)
    rule_id = rule_id_for(id_prefix, engine, kind, value)

    canonical = render(data, sid, rule_id, "")
    if canonical is None:
        return None  # no deterministic rule — prefer none over a weak one
    artifact_id = compute_artifact_id(
        language=language,
        target_platform=template.target.platform,
        category=template.category,
        content=canonical,
        rule_id=rule_id,
        source_finding_ids=list(data.finding_ids),
    )
    content = render(data, sid, rule_id, artifact_id)
    assert content is not None

    refs = [
        DetectionReference(
            title=f"MITRE ATT&CK {t}", url=f"https://{_ATTACK_URL.format(path=_attack_path(t))}"
        )
        for t in data.techniques
    ]
    refs += [DetectionReference(title=f"ThreatLens finding {fid}") for fid in data.finding_ids]

    metadata = {
        "finding_ids": ",".join(data.finding_ids),
        "rule_id": rule_id,
        "detection_id": artifact_id,
        "sid": str(sid),
        "subject": value,
        "kind": kind,
        "source": SOURCE,
    }
    if data.sources:
        metadata["sources"] = ",".join(data.sources)
    if data.techniques:
        metadata["attack"] = ",".join(data.techniques)

    return DetectionArtifact(
        id=artifact_id,
        language=language,
        target=template.target,
        title=f"Malicious {label(kind)}: {value}",
        description=_description(data),
        content=content,
        severity=data.severity,
        category=template.category,
        capabilities=template.capabilities,
        source_finding_ids=data.finding_ids,
        references=tuple(refs),
        validation=DetectionValidation(),
        rule_id=rule_id,
        metadata=metadata,
    )


def _description(data: NetRuleData) -> str:
    text = (
        f"Detects network activity involving the {label(data.kind)} {data.value}, "
        f"flagged as malicious by ThreatLens finding(s) {', '.join(data.finding_ids)}"
    )
    if data.sources:
        text += f" via {', '.join(data.sources)}"
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
