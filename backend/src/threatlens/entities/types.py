"""Canonical entity types and validation states for the detection engine.

``EntityType`` is the closed vocabulary the Universal Entity Detection Engine
classifies input into. It is intentionally a superset of the IOC subtypes so
that IOC analysis is one capability of search rather than the whole product
(see ``docs/architecture/PHASE-0-ARCHITECTURE.md`` §12).
"""

from __future__ import annotations

from enum import StrEnum


class EntityType(StrEnum):
    """The closed set of entity types the engine can resolve.

    Values are stable string identifiers safe to persist and expose over the
    API. New types are added here and backed by a detector; existing detection
    logic does not change.
    """

    # --- Network indicators ---
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"

    # --- File hashes ---
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

    # --- Structured references ---
    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    MITRE_TECHNIQUE = "mitre_technique"
    REGISTRY_KEY = "registry_key"

    # --- Host artifacts ---
    PROCESS_NAME = "process_name"
    POWERSHELL_COMMAND = "powershell_command"
    WINDOWS_API = "windows_api"
    FILE_NAME = "file_name"

    # --- Threat knowledge (soft types, reference-data backed) ---
    THREAT_ACTOR = "threat_actor"
    MALWARE_FAMILY = "malware_family"

    # --- Fallbacks ---
    FREETEXT = "freetext"
    UNKNOWN = "unknown"


class ValidationStatus(StrEnum):
    """Outcome of a detector's validation step for the resolved entity.

    - ``VALID``: the value was matched and passed type-specific validation.
    - ``INVALID``: matched a type's shape but failed validation (reserved;
      the engine currently skips failed candidates rather than emitting them).
    - ``UNVALIDATED``: no validator applies (e.g. ``UNKNOWN`` / ``FREETEXT``).
    """

    VALID = "valid"
    INVALID = "invalid"
    UNVALIDATED = "unvalidated"
