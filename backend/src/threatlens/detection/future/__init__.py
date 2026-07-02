"""Namespace for the concrete detection generators.

The Detection Engineering Framework (Phase 4.0) ships the pure engine, canonical
models, registry, templates, and validation extension points. Concrete
generators land here, each implementing
:class:`threatlens.detection.registry.DetectionGenerator` and registered in
``detection.registry.build_default_registry``:

* ``sigma`` — Sigma rules (generic SIEM). **Implemented (Phase 4.1).**
* ``yara`` — YARA file/hash signatures. **Implemented (Phase 4.2).**
* ``suricata`` / ``snort`` — network IDS/IPS signatures. *(later phase)*
* ``splunk`` (SPL) · ``sentinel`` (KQL) · ``elastic`` (EQL). *(later phase)*
* ``crowdstrike`` · ``trend_vision_one`` · ``stellar_cyber`` — EDR/XDR. *(later phase)*

Each generator is a **pure consumer** of ``InvestigationSummary``: it never
performs investigations, contacts providers, calls an AI model, or alters
findings, confidence, severity, priority, recommendations, or relationships.
"""

from __future__ import annotations

from .sigma import SigmaGenerator
from .yara import YaraGenerator

__all__ = ["SigmaGenerator", "YaraGenerator"]
