"""Splunk detection generator — native SPL (Phase 4.4).

A pure, deterministic ``DetectionGenerator`` that emits idiomatic Splunk SPL
searches from findings (never Sigma converted). Consumes only ``Finding``
objects; no providers, AI, network, or wall clock. See ``_siemcommon`` for
eligibility, deterministic identity, provenance, and validation.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...reasoning import InvestigationSummary
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
    if kind == "ip":
        return (
            f'index=* (src_ip="{v}" OR dest_ip="{v}")\n'
            "| stats count earliest(_time) as firstTime latest(_time) as lastTime "
            "by host, src_ip, dest_ip"
        )
    if kind == "domain":
        return f'index=* (query="{v}" OR url="*{v}*")\n| stats count by host, query, url'
    if kind == "url":
        return f'index=* url="{v}"\n| stats count by host, url'
    if kind == "hash":
        field = obs.subtype
        return f'index=* {field}="{v}"\n| stats count by host, {field}, file_name'
    if kind == "process":
        return (
            f'index=* process_name="{v}"\n'
            "| stats count by host, user, process_name, parent_process_name"
        )
    if kind == "registry":
        return f'index=* registry_path="{v}"\n| stats count by host, user, registry_path'
    return f'index=* ScriptBlockText="*{v}*"\n| stats count by host, user'  # powershell


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
            )
            for obs in sorted(groups, key=lambda o: (o.kind, o.value))
        ]
