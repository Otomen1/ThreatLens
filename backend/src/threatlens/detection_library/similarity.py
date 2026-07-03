"""Deterministic similarity + match classification (Phase 4.6).

Scores how closely a community rule resembles an investigation on a 0–100 scale
using pure set overlap — **no embeddings, no LLM, no fuzzy AI**. The score is a
fixed weighted sum of per-dimension Jaccard overlaps; the classification
(``EXACT`` / ``PARTIAL`` / ``RELATED`` / ``NONE``) is driven by *which*
dimensions overlap, so an exact indicator match is always ``EXACT`` regardless of
the aggregate score. Everything here is a pure function of its inputs.

Dimension weights (sum = 100):

    IOC 38 · MITRE 24 · Malware 12 · Actor 8 · Category 8 · Tags 6 · Platform 4
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities.types import EntityType
from ..providers.results import RelationshipTargetType
from ..reasoning import InvestigationSummary
from .models import CommunityRule
from .types import DetectionCategory, RuleMatchType, RulePlatform

# Dimension weights (documented contract; changing these bumps the golden).
_W_IOC = 38
_W_MITRE = 24
_W_MALWARE = 12
_W_ACTOR = 8
_W_CATEGORY = 8
_W_TAGS = 6
_W_PLATFORM = 4

# Below this score a rule sharing only a weak (theme) dimension is dropped.
_RELATED_FLOOR = 8

# EntityType → the platform its telemetry lives on.
_ENTITY_PLATFORM = {
    EntityType.IPV4: RulePlatform.NETWORK,
    EntityType.IPV6: RulePlatform.NETWORK,
    EntityType.DOMAIN: RulePlatform.NETWORK,
    EntityType.URL: RulePlatform.NETWORK,
    EntityType.PROCESS_NAME: RulePlatform.WINDOWS,
    EntityType.REGISTRY_KEY: RulePlatform.WINDOWS,
    EntityType.POWERSHELL_COMMAND: RulePlatform.WINDOWS,
    EntityType.WINDOWS_API: RulePlatform.WINDOWS,
}

# Community detection category → the finding-category tokens it speaks to.
_DETECTION_TO_FINDING = {
    DetectionCategory.NETWORK: {"malicious_infrastructure", "reputation"},
    DetectionCategory.DNS: {"malicious_infrastructure"},
    DetectionCategory.HTTP: {"malicious_infrastructure"},
    DetectionCategory.FILE: {"malware"},
    DetectionCategory.PROCESS: {"malware", "attack_pattern"},
    DetectionCategory.REGISTRY: {"malware", "attack_pattern"},
    DetectionCategory.HOST: {"malware", "attack_pattern"},
    DetectionCategory.BEHAVIORAL: {"attack_pattern"},
    DetectionCategory.VULNERABILITY: {"vulnerability"},
}


@dataclass(frozen=True)
class MatchProfile:
    """The deterministic signature of an investigation used for matching."""

    iocs: frozenset[tuple[EntityType, str]] = frozenset()
    techniques: frozenset[str] = frozenset()
    malware: frozenset[str] = frozenset()
    actors: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()
    platforms: frozenset[RulePlatform] = frozenset()


def profile_from_summary(summary: InvestigationSummary) -> MatchProfile:
    """Extract an investigation's matchable signature (pure, deterministic)."""
    iocs: set[tuple[EntityType, str]] = {
        (summary.entity_type, summary.entity_value.strip().lower())
    }
    techniques: set[str] = set()
    malware: set[str] = set()
    actors: set[str] = set()
    categories: set[str] = {c.value for c in summary.categories}
    platforms: set[RulePlatform] = set()

    for finding in summary.findings:
        iocs.add((finding.subject_type, finding.subject_value.strip().lower()))
        categories.update(c.value for c in finding.categories)
        platforms.add(_ENTITY_PLATFORM.get(finding.subject_type, RulePlatform.GENERIC))
        for rel in finding.relationships:
            target = rel.relationship.target_type
            value = rel.relationship.target_value.strip()
            if target is RelationshipTargetType.ATTACK_PATTERN:
                techniques.add(value.upper())
            elif target is RelationshipTargetType.MALWARE_FAMILY:
                malware.add(value.lower())
            elif target is RelationshipTargetType.THREAT_ACTOR:
                actors.add(value.lower())

    tags = set(categories) | malware | actors
    return MatchProfile(
        iocs=frozenset(iocs),
        techniques=frozenset(techniques),
        malware=frozenset(malware),
        actors=frozenset(actors),
        categories=frozenset(categories),
        tags=frozenset(tags),
        platforms=frozenset(platforms),
    )


@dataclass(frozen=True)
class RuleSignature:
    """The parallel signature of a community rule."""

    iocs: frozenset[tuple[EntityType, str]]
    techniques: frozenset[str]
    malware: frozenset[str]
    actors: frozenset[str]
    categories: frozenset[str]
    tags: frozenset[str]
    platforms: frozenset[RulePlatform]


def rule_signature(rule: CommunityRule) -> RuleSignature:
    """Extract a community rule's matchable signature (pure, deterministic)."""
    category_tokens = set(_DETECTION_TO_FINDING.get(rule.category, set()))
    return RuleSignature(
        iocs=frozenset((i.type, i.value.strip().lower()) for i in rule.iocs),
        techniques=frozenset(t.upper() for t in rule.mitre_techniques),
        malware=frozenset(m.lower() for m in rule.malware_families),
        actors=frozenset(a.lower() for a in rule.threat_actors),
        categories=frozenset(category_tokens),
        tags=frozenset(t.lower() for t in rule.tags) | category_tokens,
        platforms=frozenset(rule.platforms),
    )


@dataclass(frozen=True)
class ScoredMatch:
    """The full deterministic scoring of one rule against one profile."""

    match_type: RuleMatchType
    similarity: int
    coverage: int
    shared_iocs: tuple[str, ...]
    shared_techniques: tuple[str, ...]
    shared_malware: tuple[str, ...]
    shared_actors: tuple[str, ...]
    rationale: str


def _jaccard(a: frozenset[object], b: frozenset[object]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def score(profile: MatchProfile, rule: CommunityRule) -> ScoredMatch:
    """Score + classify one rule against an investigation profile (deterministic)."""
    sig = rule_signature(rule)

    ioc_shared = profile.iocs & sig.iocs
    tech_shared = profile.techniques & sig.techniques
    mal_shared = profile.malware & sig.malware
    act_shared = profile.actors & sig.actors

    similarity = round(
        _W_IOC * _jaccard(profile.iocs, sig.iocs)
        + _W_MITRE * _jaccard(profile.techniques, sig.techniques)
        + _W_MALWARE * _jaccard(profile.malware, sig.malware)
        + _W_ACTOR * _jaccard(profile.actors, sig.actors)
        + _W_CATEGORY * _jaccard(profile.categories, sig.categories)
        + _W_TAGS * _jaccard(profile.tags, sig.tags)
        + _W_PLATFORM * _jaccard(profile.platforms, sig.platforms)
    )

    match_type = _classify(
        ioc_shared, tech_shared, mal_shared, act_shared, sig, profile, similarity
    )
    return ScoredMatch(
        match_type=match_type,
        similarity=similarity,
        coverage=_coverage(profile, sig),
        shared_iocs=tuple(sorted(f"{t.value}:{v}" for t, v in ioc_shared)),
        shared_techniques=tuple(sorted(tech_shared)),
        shared_malware=tuple(sorted(mal_shared)),
        shared_actors=tuple(sorted(act_shared)),
        rationale=_rationale(ioc_shared, tech_shared, mal_shared, act_shared, match_type),
    )


def _classify(
    ioc_shared: frozenset[tuple[EntityType, str]],
    tech_shared: frozenset[str],
    mal_shared: frozenset[str],
    act_shared: frozenset[str],
    sig: RuleSignature,
    profile: MatchProfile,
    similarity: int,
) -> RuleMatchType:
    """Deterministic classification driven by which dimensions overlap."""
    if ioc_shared:
        return RuleMatchType.EXACT
    if tech_shared or mal_shared or act_shared:
        return RuleMatchType.PARTIAL
    theme = (
        (profile.categories & sig.categories)
        or (profile.tags & sig.tags)
        or (profile.platforms & sig.platforms)
    )
    if theme and similarity >= _RELATED_FLOOR:
        return RuleMatchType.RELATED
    return RuleMatchType.NONE


def _coverage(profile: MatchProfile, sig: RuleSignature) -> int:
    """Percent of the investigation's primary signals (IOCs + techniques) the rule covers."""
    primary = _primary_tokens(profile.iocs, profile.techniques)
    covered = _primary_tokens(sig.iocs, sig.techniques)
    if not primary:
        return 0
    return round(100 * len(primary & covered) / len(primary))


def _primary_tokens(
    iocs: frozenset[tuple[EntityType, str]], techniques: frozenset[str]
) -> frozenset[str]:
    """A uniform string token set over indicators + techniques (comparable)."""
    return frozenset(f"ioc:{t.value}:{v}" for t, v in iocs) | frozenset(
        f"technique:{t}" for t in techniques
    )


def _rationale(
    ioc_shared: frozenset[tuple[EntityType, str]],
    tech_shared: frozenset[str],
    mal_shared: frozenset[str],
    act_shared: frozenset[str],
    match_type: RuleMatchType,
) -> str:
    parts: list[str] = []
    if ioc_shared:
        parts.append(f"{len(ioc_shared)} shared indicator(s)")
    if tech_shared:
        parts.append(f"{len(tech_shared)} shared ATT&CK technique(s)")
    if mal_shared:
        parts.append(f"{len(mal_shared)} shared malware family(ies)")
    if act_shared:
        parts.append(f"{len(act_shared)} shared threat actor(s)")
    if not parts:
        return "Shares thematic context (category / tags / platform) with the investigation."
    return match_type.value.capitalize() + " match: " + ", ".join(parts) + "."
