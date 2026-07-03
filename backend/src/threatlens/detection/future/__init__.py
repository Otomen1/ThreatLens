"""Namespace for the concrete detection generators.

The Detection Engineering Framework (Phase 4.0) ships the pure engine, canonical
models, registry, templates, and validation extension points. Concrete
generators land here, each implementing
:class:`threatlens.detection.registry.DetectionGenerator` and registered in
``detection.registry.build_default_registry``:

* ``sigma`` — Sigma rules (generic SIEM). **Implemented (Phase 4.1).**
* ``yara`` — YARA file/hash signatures. **Implemented (Phase 4.2).**
* ``suricata`` / ``snort`` — network IDS/IPS signatures. **Implemented (Phase 4.3).**
* ``splunk`` (SPL) · ``sentinel`` (KQL) · ``elastic`` (ES|QL) · ``chronicle``
  (YARA-L) · ``qradar`` (AQL) — SIEM queries. **Implemented (Phase 4.4).**
* ``crowdstrike`` · ``trend_vision_one`` · ``stellar_cyber`` — EDR/XDR. *(later phase)*

Each generator is a **pure consumer** of ``InvestigationSummary``: it never
performs investigations, contacts providers, calls an AI model, or alters
findings, confidence, severity, priority, recommendations, or relationships.
"""

from __future__ import annotations

from .chronicle import ChronicleGenerator
from .elastic import ElasticGenerator
from .qradar import QRadarGenerator
from .sentinel import SentinelGenerator
from .sigma import SigmaGenerator
from .snort import SnortGenerator
from .splunk import SplunkGenerator
from .suricata import SuricataGenerator
from .yara import YaraGenerator

__all__ = [
    "ChronicleGenerator",
    "ElasticGenerator",
    "QRadarGenerator",
    "SentinelGenerator",
    "SigmaGenerator",
    "SnortGenerator",
    "SplunkGenerator",
    "SuricataGenerator",
    "YaraGenerator",
]
