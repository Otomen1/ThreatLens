"""Deterministic field-mapping profiles for generated detections.

Profiles keep platform field names separate from detection logic. They are
plain data so generators can receive a mapping explicitly without reading the
environment or contacting a service during generation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class FieldMappingProfile:
    """Field names used by a target platform for observable kinds."""

    name: str
    display_name: str = "Generic"
    platform: str = "generic"
    version: str = "1"
    event_source: str = "*"
    fields: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    options: Mapping[str, str] = field(default_factory=dict)

    def for_kind(self, kind: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
        """Return configured fields, falling back to the generator default."""
        values = self.fields.get(kind, default)
        return tuple(value.strip() for value in values if value.strip()) or default


GENERIC_FIELDS = FieldMappingProfile(
    name="generic",
    display_name="Generic Sigma",
    fields={
        "ip": ("src_ip", "dest_ip"),
        "domain": ("query",),
        "url": ("url",),
        "hash": ("file_hash",),
        "process": ("process_name",),
        "registry": ("registry_path",),
        "powershell": ("ScriptBlockText",),
    },
)

SPLUNK_FIELDS = FieldMappingProfile(
    name="splunk",
    display_name="Splunk CIM",
    platform="splunk",
    event_source="index=*",
    fields={
        "ip": ("src_ip", "dest_ip"),
        "domain": ("query", "url"),
        "url": ("url",),
        "hash": ("sha256", "file_hash"),
        "process": ("process_name",),
        "registry": ("registry_path",),
        "powershell": ("ScriptBlockText",),
    },
)

ELASTIC_FIELDS = FieldMappingProfile(
    name="elastic_ecs",
    display_name="Elastic ECS",
    platform="elastic",
    event_source="logs-*",
    fields={
        "ip": ("source.ip", "destination.ip"),
        "domain": ("dns.question.name", "url.domain"),
        "url": ("url.full",),
        "hash": ("file.hash.sha256", "file.hash.md5"),
        "process": ("process.name", "process.command_line"),
        "registry": ("registry.path",),
        "powershell": ("process.command_line",),
    },
)

SENTINEL_FIELDS = FieldMappingProfile(
    name="sentinel",
    display_name="Microsoft Sentinel",
    platform="sentinel",
    event_source="CommonSecurityLog",
    fields={
        "ip": ("SourceIP", "DestinationIP"),
        "domain": ("Name",),
        "url": ("RequestURL",),
        "hash": ("SHA256", "SHA1", "MD5"),
        "process": ("FileName", "ProcessCommandLine"),
        "registry": ("RegistryKey",),
        "powershell": ("ProcessCommandLine",),
    },
)
CHRONICLE_FIELDS = FieldMappingProfile(
    name="chronicle_udm",
    display_name="Google Chronicle UDM",
    platform="chronicle",
    fields={
        "ip": ("principal.ip", "target.ip"),
        "domain": ("network.dns.questions.name",),
        "url": ("target.url",),
        "hash": ("target.file.sha256",),
        "process": ("target.process.file.full_path",),
        "registry": ("target.registry.registry_key",),
        "powershell": ("target.process.command_line",),
    },
)
QRADAR_FIELDS = FieldMappingProfile(
    name="qradar",
    display_name="IBM QRadar",
    platform="qradar",
    event_source="events",
    fields={
        "ip": ("sourceip", "destinationip"),
        "domain": ("payload",),
        "url": ("payload",),
        "hash": ("payload",),
        "process": ("payload",),
        "registry": ("payload",),
        "powershell": ("payload",),
    },
)
SURICATA_FIELDS = FieldMappingProfile(
    name="suricata",
    display_name="Suricata",
    platform="suricata",
    options={"direction": "$HOME_NET any -> $EXTERNAL_NET any", "dns_field": "dns.query"},
)
SNORT_FIELDS = FieldMappingProfile(
    name="snort",
    display_name="Snort",
    platform="snort",
    options={"direction": "$HOME_NET any -> $EXTERNAL_NET any", "http_field": "http_host"},
)

DEFAULT_FIELD_MAPPINGS: Mapping[str, FieldMappingProfile] = {
    profile.name: profile
    for profile in (
        GENERIC_FIELDS,
        SPLUNK_FIELDS,
        ELASTIC_FIELDS,
        SENTINEL_FIELDS,
        CHRONICLE_FIELDS,
        QRADAR_FIELDS,
        SURICATA_FIELDS,
        SNORT_FIELDS,
    )
}


def get_field_mapping(name: str | None) -> FieldMappingProfile:
    """Resolve a known profile, safely falling back to generic fields."""
    return DEFAULT_FIELD_MAPPINGS.get((name or "generic").strip().lower(), GENERIC_FIELDS)
