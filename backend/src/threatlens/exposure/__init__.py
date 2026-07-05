"""Exposure Intelligence Framework (Phase 5.0 — architecture only).

Threat Intelligence (``providers/``) answers "is this IOC malicious?" —
Exposure Intelligence answers "where is this entity exposed?" (open ports,
certificates, passive DNS, hosting, subdomains, breaches, paste sites, …).
It is purely descriptive: it never scores, never judges maliciousness, and
never imports from ``providers/``, ``reference/``, ``reasoning/``,
``detection/``, ``detection_library/``, ``ai/``, or ``system/`` — dependency
flows one way, inward from this package to ``entities/`` only. Nothing in
those frozen subsystems imports from here either.

Phase 5.0 ships the framework — models, provider interface, registry,
config, cache, service — with **zero concrete providers**. Every code path
(registration, routing, aggregation, the service) is real and tested; it
simply has nothing registered yet. Providers arrive in Phase 5.1+ by
registering against this unmodified contract, exactly as
``providers/defaults.py`` added concrete TI providers after Phase 1.2's
framework-only milestone.
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
    "build_default_registry",
]
