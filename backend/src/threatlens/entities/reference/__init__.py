"""Curated reference data backing soft-type classification.

Soft entity types (malware family, threat actor, Windows API, process name,
PowerShell command) cannot be recognized by structural validation alone — they
are classified by lookup against curated reference data, never by an LLM
(see PHASE-0-ARCHITECTURE.md §13, §27).

These seed lists are intentionally small but real. They are designed to be
replaced/augmented in later phases by authoritative sources (MITRE ATT&CK STIX
bundle, malpedia, LOLBAS). Each module exposes a normalized lookup structure;
this package re-exports them for the detectors.
"""

from .malware_families import MALWARE_FAMILIES
from .powershell import APPROVED_VERBS, KNOWN_CMDLETS
from .processes import KNOWN_PROCESSES
from .threat_actors import THREAT_ACTORS
from .windows_apis import WINDOWS_APIS

__all__ = [
    "MALWARE_FAMILIES",
    "THREAT_ACTORS",
    "WINDOWS_APIS",
    "KNOWN_PROCESSES",
    "APPROVED_VERBS",
    "KNOWN_CMDLETS",
]
