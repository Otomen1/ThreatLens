"""Snapshot helpers for the Detection Knowledge Library golden regression.

Produces stable, diffable snapshots of (a) every normalized rule and (b) every
scenario's recommendation, so any drift in normalization or matching fails CI
until intentionally regenerated.
"""

from __future__ import annotations

from typing import Any

from threatlens.detection_library import CommunityRecommendation, CommunityRule, recommend

from .corpus import LIBRARY, SCENARIOS


def rule_snapshot(rule: CommunityRule) -> dict[str, Any]:
    """A stable snapshot of one normalized community rule."""
    return {
        "id": rule.id,
        "source": rule.source.id,
        "rule_id": rule.rule_id,
        "language": rule.language.value,
        "category": rule.category.value,
        "severity": int(rule.severity),
        "license": f"{rule.license.spdx_id}/{rule.license.support.value}",
        "content_available": rule.content is not None,
        "content_hash": rule.version.content_hash[:16],
        "mitre": list(rule.mitre_techniques),
        "iocs": [f"{i.type.value}:{i.value}" for i in rule.iocs],
        "platforms": [p.value for p in rule.platforms],
        "tags": list(rule.tags),
        "actors": list(rule.threat_actors),
        "malware": list(rule.malware_families),
    }


def recommendation_snapshot(rec: CommunityRecommendation) -> dict[str, Any]:
    """A stable snapshot of one investigation's community recommendation."""
    return {
        "entity": f"{rec.entity_type.value}:{rec.entity_value}",
        "exact": rec.exact_count,
        "partial": rec.partial_count,
        "related": rec.related_count,
        "matches": [
            {
                "rule_id": m.rule.rule_id,
                "source": m.rule.source.id,
                "type": m.match_type.value,
                "similarity": m.similarity,
                "coverage": m.coverage,
                "shared_iocs": list(m.shared_iocs),
                "shared_techniques": list(m.shared_techniques),
            }
            for m in rec.matches
        ],
    }


def build_golden() -> dict[str, Any]:
    """The full golden: every normalized rule + every scenario recommendation."""
    return {
        "rules": {rule.id: rule_snapshot(rule) for rule in LIBRARY.rules},
        "recommendations": {
            scenario.id: recommendation_snapshot(recommend(scenario.summary, LIBRARY))
            for scenario in SCENARIOS
        },
    }
