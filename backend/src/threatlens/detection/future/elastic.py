"""Elastic Security detection generator — native ES|QL (Phase 4.4).

A pure, deterministic ``DetectionGenerator`` emitting idiomatic ES|QL over ECS
fields (never Sigma converted). Consumes only ``Finding`` objects; no providers,
AI, network, or wall clock.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...reasoning import InvestigationSummary
from ..models import DetectionArtifact, DetectionTarget, DetectionTemplate
from ..registry import DetectionGenerator
from ..templates import TemplateRegistry
from ..types import DetectionCapability, DetectionCategory, DetectionLanguage
from . import _siemcommon as sc

_LANGUAGE = DetectionLanguage.ELASTIC_ESQL
_PLATFORM = "Elastic Security"
_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.LOG_QUERY})

_TEMPLATE = DetectionTemplate(
    id="elastic-esql",
    name="elastic-esql",
    language=_LANGUAGE,
    target=DetectionTarget(language=_LANGUAGE, platform="generic"),
    category=DetectionCategory.GENERIC,
    description="Elastic ES|QL query template.",
    capabilities=_CAPS,
)
TemplateRegistry().register(_TEMPLATE)


def _body(obs: sc.Observable) -> str:
    v = sc.dq(obs.value)
    kind = obs.kind
    if kind == "ip":
        return (
            f'FROM logs-*\n| WHERE source.ip == "{v}" OR destination.ip == "{v}"\n'
            "| KEEP @timestamp, source.ip, destination.ip, host.name"
        )
    if kind == "domain":
        return (
            f'FROM logs-*\n| WHERE dns.question.name == "{v}" OR url.domain == "{v}"\n'
            "| KEEP @timestamp, host.name, dns.question.name"
        )
    if kind == "url":
        return (
            f'FROM logs-*\n| WHERE url.original == "{v}"\n'
            "| KEEP @timestamp, host.name, url.original"
        )
    if kind == "hash":
        field = f"file.hash.{obs.subtype}"
        return (
            f'FROM logs-*\n| WHERE {field} == "{v}"\n'
            f"| KEEP @timestamp, host.name, file.name, {field}"
        )
    if kind == "process":
        return (
            f'FROM logs-*\n| WHERE process.name == "{v}" OR process.command_line LIKE "*{v}*"\n'
            "| KEEP @timestamp, host.name, process.name, process.command_line"
        )
    if kind == "registry":
        return (
            f'FROM logs-*\n| WHERE registry.path LIKE "*{v}*"\n'
            "| KEEP @timestamp, host.name, registry.path"
        )
    return (  # powershell
        f'FROM logs-*\n| WHERE process.command_line LIKE "*{v}*"\n'
        "| KEEP @timestamp, host.name, process.command_line"
    )


def _render(data: sc.SiemData, rule_id: str, detection_id: str, generated_at: str) -> str:
    header = sc.comment_header(data, rule_id, detection_id, generated_at, "// ")
    return f"{header}\n{_body(data.observable)}\n"


class ElasticGenerator(DetectionGenerator):
    """Generates deterministic Elastic ES|QL detections."""

    @property
    def name(self) -> str:
        return "elastic"

    @property
    def language(self) -> DetectionLanguage:
        return _LANGUAGE

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return _CAPS

    @property
    def priority(self) -> int:
        return 70

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        ts = summary.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        groups = sc.group_eligible(summary.findings)
        return [
            sc.build_artifact(
                language=_LANGUAGE,
                generator="elastic",
                platform=_PLATFORM,
                id_prefix="ela",
                template=_TEMPLATE,
                observable=obs,
                findings=groups[obs],
                generated_at_iso=ts,
                render=_render,
            )
            for obs in sorted(groups, key=lambda o: (o.kind, o.value))
        ]
