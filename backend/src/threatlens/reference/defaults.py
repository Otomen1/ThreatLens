"""The default reference-provider set.

The single place that wires concrete reference providers into a registry —
analogous to ``providers.defaults.build_default_registry``. Adding a future
knowledge provider (NVD, CWE, CAPEC) is a one-line change here and nowhere else.
"""

from __future__ import annotations

from .cwe import CweProvider
from .mitre_attack import MitreAttackProvider
from .nvd import NvdProvider
from .registry import ReferenceRegistry
from .router import ReferenceRouter


def build_default_reference_registry() -> ReferenceRegistry:
    """Build a registry populated with all production reference providers."""
    registry = ReferenceRegistry()
    registry.register(MitreAttackProvider())
    registry.register(NvdProvider())
    registry.register(CweProvider())
    return registry


def build_default_reference_router() -> ReferenceRouter:
    """Build a router over the default reference-provider registry."""
    return ReferenceRouter(build_default_reference_registry())
