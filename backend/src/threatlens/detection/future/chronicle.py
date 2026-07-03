"""Google Chronicle detection generator — native YARA-L (Phase 4.4).

A pure, deterministic ``DetectionGenerator`` emitting YARA-L 2.0 rules over UDM
fields (never Sigma converted). Consumes only ``Finding`` objects; no providers,
AI, network, or wall clock. Provenance lives in the rule's ``meta:`` section;
``detection_id``/``generated_at`` are excluded from the identity hash.
"""

from __future__ import annotations

from collections.abc import Sequence

from ... import __version__ as THREATLENS_VERSION
from ...reasoning import InvestigationSummary
from ..models import DetectionArtifact, DetectionTarget, DetectionTemplate
from ..registry import DetectionGenerator
from ..templates import TemplateRegistry
from ..types import DetectionCapability, DetectionCategory, DetectionLanguage
from . import _siemcommon as sc

_LANGUAGE = DetectionLanguage.CHRONICLE_YARA_L
_PLATFORM = "Google Chronicle"
_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.LOG_QUERY})

_TEMPLATE = DetectionTemplate(
    id="chronicle-yara-l",
    name="chronicle-yara-l",
    language=_LANGUAGE,
    target=DetectionTarget(language=_LANGUAGE, platform="generic"),
    category=DetectionCategory.GENERIC,
    description="Google Chronicle YARA-L rule template.",
    capabilities=_CAPS,
)
TemplateRegistry().register(_TEMPLATE)


def _events(obs: sc.Observable) -> str:
    v = sc.dq(obs.value)
    kind = obs.kind
    if kind == "ip":
        return f'$e.principal.ip = "{v}" or $e.target.ip = "{v}"'
    if kind == "domain":
        return f'$e.network.dns.questions.name = "{v}" nocase'
    if kind == "url":
        return f'$e.target.url = "{v}" nocase'
    if kind == "hash":
        return f'$e.target.file.{obs.subtype} = "{v}" nocase'
    if kind == "process":
        return f'$e.target.process.file.full_path = "{v}" nocase'
    if kind == "registry":
        return f'$e.target.registry.registry_key = "{v}" nocase'
    return f'$e.target.process.command_line = "{v}" nocase'  # powershell


def _meta(data: sc.SiemData, rule_id: str, detection_id: str, generated_at: str) -> str:
    pairs = [
        ("author", "ThreatLens Detection Engine"),
        ("generator", data.generator),
        ("platform", data.platform),
        ("rule_id", rule_id),
    ]
    if detection_id:
        pairs.append(("detection_id", detection_id))
    pairs += [
        ("finding_ids", ",".join(data.finding_ids)),
        ("severity", data.level),
        ("confidence", f"{data.confidence_score} ({data.confidence_band})"),
        ("mitre", ",".join(data.techniques) if data.techniques else "n/a"),
        ("ioc", f"{data.observable.kind}={data.observable.value}"),
    ]
    if generated_at:
        pairs.append(("generated_at", generated_at))
    pairs.append(("engine_version", THREATLENS_VERSION))
    return "\n".join(f'        {key} = "{sc.dq(value)}"' for key, value in pairs)


def _render(data: sc.SiemData, rule_id: str, detection_id: str, generated_at: str) -> str:
    slug = sc.rule_slug("chr", data.observable.kind, data.observable.value)
    return (
        f"rule {slug}\n"
        "{\n"
        "    meta:\n"
        f"{_meta(data, rule_id, detection_id, generated_at)}\n"
        "    events:\n"
        f"        {_events(data.observable)}\n"
        "    condition:\n"
        "        $e\n"
        "}\n"
    )


class ChronicleGenerator(DetectionGenerator):
    """Generates deterministic Google Chronicle YARA-L detections."""

    @property
    def name(self) -> str:
        return "chronicle"

    @property
    def language(self) -> DetectionLanguage:
        return _LANGUAGE

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return _CAPS

    @property
    def priority(self) -> int:
        return 80

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        ts = summary.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        groups = sc.group_eligible(summary.findings)
        return [
            sc.build_artifact(
                language=_LANGUAGE,
                generator="chronicle",
                platform=_PLATFORM,
                id_prefix="chr",
                template=_TEMPLATE,
                observable=obs,
                findings=groups[obs],
                generated_at_iso=ts,
                render=_render,
            )
            for obs in sorted(groups, key=lambda o: (o.kind, o.value))
        ]
