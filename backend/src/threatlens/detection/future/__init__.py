"""Reserved namespace for future detection generators (later phases).

The Detection Engineering Framework (Phase 4.0) ships the pure engine, canonical
models, registry, templates, and validation extension points — but **no
generators and no rule generation**. Concrete generators land here in later
phases, one subpackage per language, each implementing
:class:`threatlens.detection.registry.DetectionGenerator` and registered in
``detection.registry.build_default_registry``:

* ``sigma/``            — Sigma rules (generic SIEM)
* ``yara/``             — YARA signatures (file/memory)
* ``suricata/`` ``snort/`` — network IDS/IPS signatures
* ``splunk/``           — Splunk SPL
* ``sentinel/``         — Microsoft Sentinel KQL
* ``elastic/``          — Elastic EQL
* ``crowdstrike/`` ``trend_vision_one/`` ``stellar_cyber/`` — EDR/XDR content

Each generator is a **pure consumer** of ``InvestigationSummary``: it never
performs investigations, contacts providers, calls an AI model, or alters
findings, confidence, severity, priority, recommendations, or relationships. This
package intentionally contains no implementations yet.
"""

from __future__ import annotations
