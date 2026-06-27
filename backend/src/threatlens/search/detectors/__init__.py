"""Detector implementations and default registration.

:func:`register_default_detectors` is the single place that enumerates the
Phase 1.1 detector set. Adding a new entity type means writing a detector and
adding one line here — existing detectors and the engine are untouched.
Detectors are listed in priority order for readability; the registry sorts
defensively regardless.
"""

from __future__ import annotations

from ..registry import EntityRegistry
from .base import DetectionContext, EntityDetector
from .hashes import Md5Detector, Sha1Detector, Sha256Detector
from .host_artifacts import (
    PowerShellCommandDetector,
    ProcessNameDetector,
    WindowsApiDetector,
)
from .identifiers import CveDetector, CweDetector, MitreTechniqueDetector, RegistryKeyDetector
from .network import (
    DomainDetector,
    EmailDetector,
    Ipv4Detector,
    Ipv6Detector,
    UrlDetector,
)
from .threat_knowledge import MalwareFamilyDetector, ThreatActorDetector

# Priority order (low -> high). See each detector's ``priority`` for the source
# of truth; this ordering is what disambiguates overlapping inputs.
DEFAULT_DETECTORS: tuple[type[EntityDetector], ...] = (
    UrlDetector,
    EmailDetector,
    Ipv4Detector,
    Ipv6Detector,
    Md5Detector,
    Sha1Detector,
    Sha256Detector,
    CveDetector,
    CweDetector,
    MitreTechniqueDetector,
    RegistryKeyDetector,
    DomainDetector,
    ProcessNameDetector,
    PowerShellCommandDetector,
    WindowsApiDetector,
    ThreatActorDetector,
    MalwareFamilyDetector,
)


def register_default_detectors(registry: EntityRegistry) -> None:
    """Register every Phase 1.1 detector into ``registry``."""
    for detector_cls in DEFAULT_DETECTORS:
        registry.register(detector_cls())


__all__ = [
    "DetectionContext",
    "EntityDetector",
    "DEFAULT_DETECTORS",
    "register_default_detectors",
]
