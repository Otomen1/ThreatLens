"""Deterministic field-mapping profiles for generated detections.

Profiles keep platform field names separate from detection logic. They are
plain data so generators can receive a mapping explicitly without reading the
environment or contacting a service during generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class FieldMappingProfile:
    """Field names used by a target platform for observable kinds."""

    name: str
    fields: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def for_kind(self, kind: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
        """Return configured fields, falling back to the generator default."""
        values = self.fields.get(kind, default)
        return tuple(value.strip() for value in values if value.strip()) or default


GENERIC_FIELDS = FieldMappingProfile(
    name="generic",
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

DEFAULT_FIELD_MAPPINGS: Mapping[str, FieldMappingProfile] = {
    profile.name: profile for profile in (GENERIC_FIELDS, SPLUNK_FIELDS, ELASTIC_FIELDS)
}


def get_field_mapping(name: str | None) -> FieldMappingProfile:
    """Resolve a known profile, safely falling back to generic fields."""
    return DEFAULT_FIELD_MAPPINGS.get((name or "generic").strip().lower(), GENERIC_FIELDS)
