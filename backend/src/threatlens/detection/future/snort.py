"""Snort detection generator — network IDS/IPS rules (Phase 4.3).

A pure, deterministic :class:`~threatlens.detection.registry.DetectionGenerator`
that converts network-observable findings (malicious IP / domain / URL) into
minimal, valid Snort (2.9-style) rules. Consumes **only** ``Finding`` objects —
no providers, no AI, no network, no wall clock.

Mappings: IP → ``alert ip`` to the address; domain → HTTP ``Host`` content match
(``http_header``); URL → HTTP host + URI content match (``http_header`` +
``http_uri``). Hashes, CVE/CWE/CAPEC, techniques/actors, file-only and
informational findings never yield a rule. Shares eligibility, deterministic SID
allocation, and traceability with Suricata via ``_netrules`` — only the rule
syntax differs.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...reasoning import InvestigationSummary
from ..models import DetectionArtifact, DetectionTarget, DetectionTemplate
from ..registry import DetectionGenerator
from ..templates import TemplateRegistry
from ..types import DetectionCapability, DetectionCategory, DetectionLanguage
from . import _netrules as net

_LANGUAGE = DetectionLanguage.SNORT
_ENGINE = "snort"
_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.NETWORK_SIGNATURE})


def _build_templates() -> dict[DetectionCategory, DetectionTemplate]:
    registry = TemplateRegistry()
    templates: dict[DetectionCategory, DetectionTemplate] = {}
    for category in (DetectionCategory.NETWORK, DetectionCategory.DNS, DetectionCategory.HTTP):
        template = DetectionTemplate(
            id=f"snort-{category.value}",
            name=f"snort-{category.value}",
            language=_LANGUAGE,
            target=DetectionTarget(language=_LANGUAGE, platform="generic"),
            category=category,
            description=f"Snort network template ({category.value}).",
            capabilities=_CAPS,
        )
        registry.register(template)
        templates[category] = template
    return templates


_TEMPLATES = _build_templates()


class SnortGenerator(DetectionGenerator):
    """Generates deterministic Snort rules from network-observable findings."""

    @property
    def name(self) -> str:
        return "snort"

    @property
    def language(self) -> DetectionLanguage:
        return _LANGUAGE

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return _CAPS

    @property
    def priority(self) -> int:
        return 40

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        groups = net.group_eligible(summary.findings)
        artifacts: list[DetectionArtifact] = []
        for key in sorted(groups):
            kind, value = key
            artifact = net.build_artifact(
                language=_LANGUAGE,
                engine=_ENGINE,
                id_prefix="snr",
                template=_TEMPLATES[net.CATEGORY_BY_KIND[kind]],
                kind=kind,
                value=value,
                findings=groups[key],
                render=_render,
            )
            if artifact is not None:
                artifacts.append(artifact)
        return artifacts


def _render(data: net.NetRuleData, sid: int, rule_id: str, detection_id: str) -> str | None:
    msg = f"ThreatLens: Malicious {net.label(data.kind)} {data.value}"
    options = [f'msg:"{net.msg_escape(msg)}"']

    if data.kind == "ip":
        header = f"alert ip $HOME_NET any -> {data.value} any"
    elif data.kind == "domain":
        header = "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS"
        options += [
            "flow:to_server,established",
            f'content:"{net.content_encode(data.value)}"',
            "http_header",
            "nocase",
        ]
    else:  # url
        parts = net.url_parts(data.value)
        if parts is None:
            return None
        host, path = parts
        header = "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS"
        options += [
            "flow:to_server,established",
            f'content:"{net.content_encode(host)}"',
            "http_header",
            "nocase",
            f'content:"{net.content_encode(path)}"',
            "http_uri",
            "nocase",
        ]

    options.append(f"classtype:{net.CLASSTYPE}")
    options += [f"reference:url,{ref}" for ref in net.references(data.techniques)]
    options.append(net.metadata_option(data, rule_id, detection_id))
    options.append(f"priority:{data.priority}")
    options.append(f"sid:{sid}")
    options.append("rev:1")
    return f"{header} ({'; '.join(options)};)\n"
