"""MITRE ATT&CK reference provider package.

The first concrete reference provider and the blueprint for future knowledge
sources: a ``dataset`` module that loads/indexes an offline STIX bundle, a
``provider`` that normalizes typed views into the canonical IntelligenceResult,
and a bundled seed dataset under ``data/`` so it works offline out of the box.
"""

from __future__ import annotations

from .dataset import Group, MitreAttackDataset, Software, Technique
from .provider import MitreAttackProvider

__all__ = [
    "Group",
    "MitreAttackDataset",
    "MitreAttackProvider",
    "Software",
    "Technique",
]
