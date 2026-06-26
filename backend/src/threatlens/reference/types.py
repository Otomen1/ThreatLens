"""Vocabularies for reference knowledge providers.

Reference providers expose *kinds of knowledge* rather than the TI capabilities
(reputation, abuse, etc.). These are separate on purpose — the two frameworks
solve different problems and do not share one capability vocabulary.
"""

from __future__ import annotations

from enum import StrEnum


class ReferenceCapability(StrEnum):
    """A kind of structured knowledge a reference provider exposes."""

    TECHNIQUE = "technique"  # MITRE ATT&CK techniques
    TACTIC = "tactic"  # MITRE ATT&CK tactics
    GROUP = "group"  # ATT&CK groups (adversaries)
    SOFTWARE = "software"  # ATT&CK software (malware/tools)
    VULNERABILITY = "vulnerability"  # CVE / NVD
    WEAKNESS = "weakness"  # CWE
    ATTACK_PATTERN = "attack_pattern"  # CAPEC
    CROSS_REFERENCE = "cross_reference"  # links between datasets
    KNOWLEDGE_BASE = "knowledge_base"  # internal KB / report index
