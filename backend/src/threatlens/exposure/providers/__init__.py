"""Concrete exposure providers (Phase 5.1+).

Empty in Phase 5.0 — the framework in the parent package is complete and
tested with zero providers registered. A future provider (Shodan, Censys,
GreyNoise, HIBP, SecurityTrails, …) implements ``exposure.ExposureProvider``
and is wired into a registry via ``exposure.registry.build_default_registry``,
exactly as ``providers/defaults.py`` wires concrete Threat Intelligence
providers today.
"""

from __future__ import annotations
