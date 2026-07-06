"""Concrete identity providers.

Empty in Phase 6.0 (framework only). Later phases add HIBP (breaches,
credential exposure), Microsoft Entra ID, Okta, JumpCloud, Active Directory,
Google Workspace, … — each implements ``identity.IdentityProvider`` and is
wired into a registry via ``identity.registry.build_default_registry``,
exactly as ``exposure/providers/`` wires concrete Exposure providers and
``providers/defaults.py`` wires concrete Threat Intelligence providers.
"""

from __future__ import annotations

__all__: list[str] = []
