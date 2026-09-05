"""Microsoft Sentinel detection generator — native KQL (Phase 4.4).

A pure, deterministic ``DetectionGenerator`` emitting idiomatic KQL over
Sentinel/Defender tables (never Sigma converted). Consumes only ``Finding``
objects; no providers, AI, network, or wall clock.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...reasoning import InvestigationSummary
from ..field_mappings import SENTINEL_FIELDS
from ..models import DetectionArtifact, DetectionTarget, DetectionTemplate
from ..registry import DetectionGenerator
from ..templates import TemplateRegistry
from ..types import DetectionCapability, DetectionCategory, DetectionLanguage
from . import _siemcommon as sc

_LANGUAGE = DetectionLanguage.SENTINEL_KQL
_PLATFORM = "Microsoft Sentinel"
_CAPS = frozenset({DetectionCapability.IOC_MATCH, DetectionCapability.LOG_QUERY})

_TEMPLATE = DetectionTemplate(
    id="sentinel-kql",
    name="sentinel-kql",
    language=_LANGUAGE,
    target=DetectionTarget(language=_LANGUAGE, platform="generic"),
    category=DetectionCategory.GENERIC,
    description="Microsoft Sentinel KQL query template.",
    capabilities=_CAPS,
)
TemplateRegistry().register(_TEMPLATE)


def _body(obs: sc.Observable) -> str:
    v = sc.dq(obs.value)
    kind = obs.kind
    fields = SENTINEL_FIELDS.for_kind(kind)
    if kind == "ip":
        return (
            f"{SENTINEL_FIELDS.event_source}\n"
            f'| where {fields[0]} == "{v}" or {fields[1]} == "{v}"\n'
            f"| project TimeGenerated, DeviceVendor, {fields[0]}, {fields[1]}"
        )
    if kind == "domain":
        return (
            f'DnsEvents\n| where {fields[0]} =~ "{v}"\n'
            f"| project TimeGenerated, Computer, {fields[0]}, IPAddresses"
        )
    if kind == "url":
        return (
            f'{SENTINEL_FIELDS.event_source}\n| where {fields[0]} has "{v}"\n'
            f"| project TimeGenerated, SourceIP, {fields[0]}"
        )
    if kind == "hash":
        field = obs.subtype.upper()
        return (
            f'DeviceFileEvents\n| where {field} == "{v}"\n'
            f"| project TimeGenerated, DeviceName, FileName, {field}"
        )
    if kind == "process":
        return (
            f'DeviceProcessEvents\n| where FileName =~ "{v}" or ProcessCommandLine has "{v}"\n'
            "| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine"
        )
    if kind == "registry":
        return (
            f'DeviceRegistryEvents\n| where RegistryKey has "{v}"\n'
            "| project TimeGenerated, DeviceName, RegistryKey, RegistryValueData"
        )
    return (  # powershell
        'DeviceProcessEvents\n| where FileName =~ "powershell.exe" '
        f'and ProcessCommandLine has "{v}"\n'
        "| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine"
    )


def _render(data: sc.SiemData, rule_id: str, detection_id: str, generated_at: str) -> str:
    header = sc.comment_header(data, rule_id, detection_id, generated_at, "// ")
    return f"{header}\n{_body(data.observable)}\n"


class SentinelGenerator(DetectionGenerator):
    """Generates deterministic Microsoft Sentinel KQL detections."""

    @property
    def name(self) -> str:
        return "sentinel"

    @property
    def language(self) -> DetectionLanguage:
        return _LANGUAGE

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        return _CAPS

    @property
    def priority(self) -> int:
        return 60

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        ts = summary.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        groups = sc.group_eligible(summary.findings)
        return [
            sc.build_artifact(
                language=_LANGUAGE,
                generator="sentinel",
                platform=_PLATFORM,
                id_prefix="sen",
                template=_TEMPLATE,
                observable=obs,
                findings=groups[obs],
                generated_at_iso=ts,
                render=_render,
                mapping_profile=SENTINEL_FIELDS.name,
                mapping_version=SENTINEL_FIELDS.version,
            )
            for obs in sorted(groups, key=lambda o: (o.kind, o.value))
        ]
