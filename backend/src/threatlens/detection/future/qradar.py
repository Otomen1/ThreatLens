"""IBM QRadar detection generator — native AQL (Phase 4.4).

A pure, deterministic ``DetectionGenerator`` emitting Ariel Query Language (AQL)
searches (never Sigma converted). Consumes only ``Finding`` objects; no
providers, AI, network, or wall clock. IP IOCs use normalized fields; other IOCs
use a payload contains-match, which AQL expresses idiomatically.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...reasoning import InvestigationSummary
from ..models import DetectionArtifact, DetectionTarget, DetectionTemplate
from ..registry import DetectionGenerator
from ..templates import TemplateRegistry
from ..types import DetectionCapability, DetectionCategory, DetectionLanguage
from . import _siemcommon as sc

_LANGUAGE = DetectionLanguage.QRADAR_AQL
_PLATFORM = "IBM QRadar"
_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.LOG_QUERY})

_TEMPLATE = DetectionTemplate(
    id="qradar-aql",
    name="qradar-aql",
    language=_LANGUAGE,
    target=DetectionTarget(language=_LANGUAGE, platform="generic"),
    category=DetectionCategory.GENERIC,
    description="IBM QRadar AQL query template.",
    capabilities=_CAPS,
)
TemplateRegistry().register(_TEMPLATE)


def _body(obs: sc.Observable) -> str:
    v = sc.aql(obs.value)
    if obs.kind == "ip":
        return (
            "SELECT QIDNAME(qid) AS event, sourceip, destinationip, username "
            f"FROM events WHERE sourceip = '{v}' OR destinationip = '{v}' LAST 7 DAYS"
        )
    return (
        "SELECT QIDNAME(qid) AS event, sourceip, destinationip, UTF8(payload) AS payload "
        f"FROM events WHERE UTF8(payload) ILIKE '%{v}%' LAST 7 DAYS"
    )


def _render(data: sc.SiemData, rule_id: str, detection_id: str, generated_at: str) -> str:
    header = "/*\n" + "\n".join(sc.meta_lines(data, rule_id, detection_id, generated_at)) + "\n*/"
    return f"{header}\n{_body(data.observable)}\n"


class QRadarGenerator(DetectionGenerator):
    """Generates deterministic IBM QRadar AQL detections."""

    @property
    def name(self) -> str:
        return "qradar"

    @property
    def language(self) -> DetectionLanguage:
        return _LANGUAGE

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return _CAPS

    @property
    def priority(self) -> int:
        return 90

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        ts = summary.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        groups = sc.group_eligible(summary.findings)
        return [
            sc.build_artifact(
                language=_LANGUAGE,
                generator="qradar",
                platform=_PLATFORM,
                id_prefix="qra",
                template=_TEMPLATE,
                observable=obs,
                findings=groups[obs],
                generated_at_iso=ts,
                render=_render,
            )
            for obs in sorted(groups, key=lambda o: (o.kind, o.value))
        ]
