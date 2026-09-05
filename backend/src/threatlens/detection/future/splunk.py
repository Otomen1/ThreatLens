"""Splunk detection generator — native SPL (Phase 4.4).

A pure, deterministic ``DetectionGenerator`` that emits idiomatic Splunk SPL
searches from findings (never Sigma converted). Consumes only ``Finding``
objects; no providers, AI, network, or wall clock. See ``_siemcommon`` for
eligibility, deterministic identity, provenance, and validation.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...reasoning import InvestigationSummary
from ..field_mappings import SPLUNK_FIELDS
from ..models import DetectionArtifact, DetectionTarget, DetectionTemplate
from ..registry import DetectionGenerator
from ..templates import TemplateRegistry
from ..types import DetectionCapability, DetectionCategory, DetectionLanguage
from . import _siemcommon as sc

_LANGUAGE = DetectionLanguage.SPLUNK_SPL
_PLATFORM = "Splunk Enterprise Security"
_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.LOG_QUERY})

_TEMPLATE = DetectionTemplate(
    id="splunk-spl",
    name="splunk-spl",
    language=_LANGUAGE,
    target=DetectionTarget(language=_LANGUAGE, platform="generic"),
    category=DetectionCategory.GENERIC,
    description="Splunk SPL query template.",
    capabilities=_CAPS,
)
TemplateRegistry().register(_TEMPLATE)  # reusable template (registry pattern)


def _body(obs: sc.Observable) -> str:
    v = sc.dq(obs.value)
    kind = obs.kind
    fields = SPLUNK_FIELDS.for_kind(kind)
    source = SPLUNK_FIELDS.event_source
    if kind == "ip":
        source_field, destination_field = fields
        return (
            f'{source} ({source_field}="{v}" OR {destination_field}="{v}")\n'
            "| stats count earliest(_time) as firstTime latest(_time) as lastTime "
            f"by host, {source_field}, {destination_field}"
        )
    if kind == "domain":
        search = f'{source} ({fields[0]}="{v}" OR {fields[1]}="*{v}*")'
        return f"{search}\n| stats count by host, {fields[0]}, {fields[1]}"
    if kind == "url":
        return f'{source} {fields[0]}="{v}"\n| stats count by host, {fields[0]}'
    if kind == "hash":
        field = fields[0]
        return f'index=* {field}="{v}"\n| stats count by host, {field}, file_name'
    if kind == "process":
        return f'{source} {fields[0]}="{v}"\n| stats count by host, user, {fields[0]}'
    if kind == "registry":
        return f'{source} {fields[0]}="{v}"\n| stats count by host, user, {fields[0]}'
    return f'{source} {fields[0]}="*{v}*"\n| stats count by host, user'


def _render(data: sc.SiemData, rule_id: str, detection_id: str, generated_at: str) -> str:
    header = "```\n" + "\n".join(sc.meta_lines(data, rule_id, detection_id, generated_at)) + "\n```"
    return f"{header}\n{_body(data.observable)}\n"


class SplunkGenerator(DetectionGenerator):
    """Generates deterministic Splunk SPL detections."""

    @property
    def name(self) -> str:
        return "splunk"

    @property
    def language(self) -> DetectionLanguage:
        return _LANGUAGE

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return _CAPS

    @property
    def priority(self) -> int:
        return 50

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        ts = summary.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        groups = sc.group_eligible(summary.findings)
        return [
            sc.build_artifact(
                language=_LANGUAGE,
                generator="splunk",
                platform=_PLATFORM,
                id_prefix="spl",
                template=_TEMPLATE,
                observable=obs,
                findings=groups[obs],
                generated_at_iso=ts,
                render=_render,
                mapping_profile=SPLUNK_FIELDS.name,
                mapping_version=SPLUNK_FIELDS.version,
            )
            for obs in sorted(groups, key=lambda o: (o.kind, o.value))
        ]
