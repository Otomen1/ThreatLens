"""The default provider set.

The single place that wires concrete providers into a registry — analogous to
``search/detectors.register_default_detectors``. Adding a provider in a later
phase is a one-line change here and nowhere else.
"""

from __future__ import annotations

from .abuseipdb import AbuseIPDBProvider
from .malwarebazaar import MalwareBazaarProvider
from .otx import OTXProvider
from .registry import ProviderRegistry
from .router import ProviderRouter
from .urlhaus import UrlhausProvider


def build_default_registry() -> ProviderRegistry:
    """Build a registry populated with all production providers."""
    registry = ProviderRegistry()
    registry.register(MalwareBazaarProvider())
    registry.register(UrlhausProvider())
    registry.register(AbuseIPDBProvider())
    registry.register(OTXProvider())
    return registry


def build_default_router() -> ProviderRouter:
    """Build a router over the default provider registry."""
    return ProviderRouter(build_default_registry())
