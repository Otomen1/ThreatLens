"""Concrete exposure providers.

Phase 5.1 adds the first: :class:`~threatlens.exposure.providers.shodan.ShodanProvider`
(open ports, services, certificates, hosting/ASN for IPv4/IPv6). Later phases
add Censys, GreyNoise, HIBP, SecurityTrails, … — each implements
``exposure.ExposureProvider`` and is wired into a registry via
``exposure.registry.build_default_registry``, exactly as ``providers/defaults.py``
wires concrete Threat Intelligence providers.
"""

from __future__ import annotations

from .shodan import ShodanProvider

__all__ = ["ShodanProvider"]
