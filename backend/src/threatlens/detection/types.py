"""Enumerations for the Detection Engineering Framework (Phase 4.0).

Closed, typed vocabularies shared across the detection models, engine, registry,
and templates. Mirrors the style of ``reasoning.models`` and ``providers.types``:
ordinal severities are ``IntEnum`` (comparable), everything else is ``StrEnum``
(stable, display-friendly, JSON-native).

The framework ships no generators in this phase; these enums define the space the
future Sigma / YARA / Suricata / Snort / SIEM generators register into.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class DetectionLanguage(StrEnum):
    """The rule language / platform dialect a detection artifact is written in.

    Extended as generators land in later phases. ``GENERIC`` is a
    language-neutral placeholder used by templates and tests.
    """

    SIGMA = "sigma"
    YARA = "yara"
    SURICATA = "suricata"
    SNORT = "snort"
    SPLUNK_SPL = "splunk_spl"
    SENTINEL_KQL = "sentinel_kql"
    ELASTIC_EQL = "elastic_eql"
    CROWDSTRIKE = "crowdstrike"
    TREND_VISION_ONE = "trend_vision_one"
    STELLAR_CYBER = "stellar_cyber"
    GENERIC = "generic"


class DetectionCategory(StrEnum):
    """The telemetry domain a detection operates over."""

    NETWORK = "network"
    HOST = "host"
    FILE = "file"
    PROCESS = "process"
    REGISTRY = "registry"
    DNS = "dns"
    HTTP = "http"
    EMAIL = "email"
    IDENTITY = "identity"
    CLOUD = "cloud"
    VULNERABILITY = "vulnerability"
    BEHAVIORAL = "behavioral"
    GENERIC = "generic"


class DetectionSeverity(IntEnum):
    """How urgent a detection is *if it fires*.

    Ordinal and value-aligned with :class:`reasoning.models.Severity` so a
    finding's severity can be **copied** (never re-derived) into an artifact.
    """

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DetectionCapability(StrEnum):
    """The kind of detection content a generator can emit.

    A generator declares its capabilities so the registry/router (future) can
    match findings to the generators able to express them.
    """

    IOC_MATCH = "ioc_match"
    HASH_SIGNATURE = "hash_signature"
    NETWORK_SIGNATURE = "network_signature"
    LOG_QUERY = "log_query"
    BEHAVIORAL = "behavioral"
    CORRELATION = "correlation"


class DetectionValidationStatus(StrEnum):
    """Outcome of validating an artifact against its language/toolchain.

    Every artifact is ``UNVALIDATED`` in this phase — validators are defined as
    extension points only (see ``detection.registry.DetectionValidator``) and
    implemented in later phases.
    """

    UNVALIDATED = "unvalidated"
    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
