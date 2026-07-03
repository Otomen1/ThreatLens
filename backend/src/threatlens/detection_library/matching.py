"""Match an investigation against the library → community recommendations (Phase 4.6).

Given an :class:`InvestigationSummary`, deterministically score every community
rule (see :mod:`similarity`) and return the ranked exact / partial / related
matches. This is strictly downstream and advisory: it never generates content,
never touches the investigation, and never merges community rules with the
Detection Engine's generated ones — provenance stays explicit on every match.
"""

from __future__ import annotations

from ..reasoning import InvestigationSummary
from .library import DetectionLibrary
from .models import CommunityRecommendation, RuleMatch
from .similarity import ScoredMatch, profile_from_summary, score
from .types import RuleMatchType

_RANK = {RuleMatchType.EXACT: 0, RuleMatchType.PARTIAL: 1, RuleMatchType.RELATED: 2}

DEFAULT_LIMIT = 25


def recommend(
    summary: InvestigationSummary,
    library: DetectionLibrary,
    *,
    limit: int = DEFAULT_LIMIT,
) -> CommunityRecommendation:
    """Rank the library's community rules against ``summary`` (deterministic)."""
    profile = profile_from_summary(summary)

    scored: list[tuple[ScoredMatch, RuleMatch]] = []
    for rule in library.rules:
        sm = score(profile, rule)
        if sm.match_type is RuleMatchType.NONE:
            continue
        scored.append(
            (
                sm,
                RuleMatch(
                    rule=rule,
                    match_type=sm.match_type,
                    similarity=sm.similarity,
                    coverage=sm.coverage,
                    shared_iocs=sm.shared_iocs,
                    shared_techniques=sm.shared_techniques,
                    shared_malware=sm.shared_malware,
                    shared_actors=sm.shared_actors,
                    rationale=sm.rationale,
                ),
            )
        )

    # Deterministic ranking: match strength, then score/coverage, then provenance.
    scored.sort(
        key=lambda pair: (
            _RANK[pair[0].match_type],
            -pair[0].similarity,
            -pair[0].coverage,
            pair[1].rule.source.priority,
            pair[1].rule.source.id,
            pair[1].rule.id,
        )
    )
    matches = tuple(match for _, match in scored[:limit])

    return CommunityRecommendation(
        entity_type=summary.entity_type,
        entity_value=summary.entity_value,
        matches=matches,
        exact_count=sum(m.match_type is RuleMatchType.EXACT for m in matches),
        partial_count=sum(m.match_type is RuleMatchType.PARTIAL for m in matches),
        related_count=sum(m.match_type is RuleMatchType.RELATED for m in matches),
        library_version=library.version,
        sync_status=library.sync_status,
        generated_at=summary.generated_at,  # inherited — the matcher reads no clock
    )
