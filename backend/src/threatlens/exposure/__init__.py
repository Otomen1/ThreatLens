"""Exposure Intelligence Framework (Phase 5.0 architecture + Phase 5.1 providers).

Threat Intelligence (``providers/``) answers "is this IOC malicious?" —
Exposure Intelligence answers "where is this entity exposed?" (open ports,
certificates, passive DNS, hosting, subdomains, breaches, paste sites, …).
It is purely descriptive: it never scores, never judges maliciousness, and
shares no models, registry, or provider logic with Threat Intelligence —
dependency flows one way, inward from this package to ``entities/`` only.
Nothing in the frozen v1.x subsystems imports from here. The one narrow,
disclosed exception is a single provider (``providers/shodan.py``) reusing
``providers/http.py``'s generic, dependency-free ``HttpClient`` transport
rather than duplicating an HTTP layer — see
``docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md``.

Phase 5.0 shipped the framework — models, provider interface, registry,
config, cache, service — with zero concrete providers; every code path
(registration, routing, aggregation, the service) was already real and
tested. Phase 5.1 registers the first concrete provider, ``ShodanProvider``,
against that unmodified contract, exactly as ``providers/defaults.py`` added
concrete TI providers after Phase 1.2's framework-only milestone.
"""

from __future__ import annotations

from .cache import ExposureCache, InMemoryExposureCache
from .config import ExposureConfig
from .exceptions import DuplicateExposureProviderError, ExposureConfigurationError, ExposureError
from .models import (
    ExposureAsset,
    ExposureCapability,
    ExposureFinding,
    ExposureFindingError,
    ExposureMetadata,
    ExposureProviderHealth,
    ExposureProviderMetadata,
    ExposureProviderStatus,
    ExposureReference,
    ExposureStatistics,
    ExposureStatus,
    ExposureSummary,
)
from .provider import ExposureProvider
from .providers import ShodanProvider
from .registry import ExposureRegistry, build_default_registry
from .service import EXPOSURE_FRAMEWORK_VERSION, ExposureService

__all__ = [
    "EXPOSURE_FRAMEWORK_VERSION",
    "DuplicateExposureProviderError",
    "ExposureAsset",
    "ExposureCache",
    "ExposureCapability",
    "ExposureConfig",
    "ExposureConfigurationError",
    "ExposureError",
    "ExposureFinding",
    "ExposureFindingError",
    "ExposureMetadata",
    "ExposureProvider",
    "ExposureProviderHealth",
    "ExposureProviderMetadata",
    "ExposureProviderStatus",
    "ExposureReference",
    "ExposureRegistry",
    "ExposureService",
    "ExposureStatistics",
    "ExposureStatus",
    "ExposureSummary",
    "InMemoryExposureCache",
    "ShodanProvider",
    "build_default_registry",
]
