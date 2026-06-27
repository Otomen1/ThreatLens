"""Static, versioned knobs shared by the EvidenceAssembler and ConfidenceScorer.

Everything here is explicit data, not logic — provider authority, evidence-type
base weights and dimensions, reputation lifting, and the freshness decay. Kept in
one module so the two pure components share a single source of truth (and so a
future config-override layer has one place to target).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ..providers.results import EvidenceType, ReputationLevel
from .models import EvidenceDimension, EvidencePolarity

# --------------------------------------------------------------------------- #
# Provider authority (0..1) and authority "family" (for echo-chamber guarding)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AuthorityEntry:
    """A provider's reliability and the upstream family it belongs to."""

    authority: float  # 0..1
    family: str


_DEFAULT_AUTHORITY = 0.4

# Explicit, versioned, overridable. Authoritative datasets outrank community
# feeds; URLhaus + MalwareBazaar share the abuse.ch family so mirrored feeds
# cannot manufacture corroboration.
AUTHORITY_MAP: dict[str, AuthorityEntry] = {
    "nvd": AuthorityEntry(0.95, "nist"),
    "mitre_attack": AuthorityEntry(0.90, "mitre"),
    "cwe": AuthorityEntry(0.90, "mitre"),
    "capec": AuthorityEntry(0.85, "mitre"),
    "urlhaus": AuthorityEntry(0.70, "abuse.ch"),
    "malwarebazaar": AuthorityEntry(0.70, "abuse.ch"),
    "abuseipdb": AuthorityEntry(0.60, "abuseipdb"),
    "otx": AuthorityEntry(0.60, "otx"),
}


def authority_of(provider: str) -> AuthorityEntry:
    """Authority entry for ``provider``; unknown providers get a modest default."""
    entry = AUTHORITY_MAP.get(provider)
    if entry is not None:
        return entry
    return AuthorityEntry(authority=_DEFAULT_AUTHORITY, family=provider)


def max_authority(sources: list[str]) -> float:
    """Highest authority among contributing providers (default if none)."""
    if not sources:
        return _DEFAULT_AUTHORITY
    return max(authority_of(s).authority for s in sources)


def families(sources: list[str]) -> set[str]:
    """The distinct authority families among contributing providers."""
    return {authority_of(s).family for s in sources}


# --------------------------------------------------------------------------- #
# Evidence-type base weights, dimensions, and polarity
# --------------------------------------------------------------------------- #

_DEFAULT_BASE_WEIGHT = 0.3

EVIDENCE_BASE_WEIGHT: dict[EvidenceType, float] = {
    EvidenceType.BLOCKLIST: 1.0,
    EvidenceType.DETECTION: 0.9,
    EvidenceType.ABUSE_CONFIDENCE: 0.8,
    EvidenceType.SANDBOX_OBSERVATION: 0.7,
    EvidenceType.MALWARE_FAMILY: 0.7,
    EvidenceType.PULSE_MATCH: 0.6,
    EvidenceType.CLASSIFICATION: 0.6,
    EvidenceType.COMMUNICATION: 0.5,
    EvidenceType.CATEGORY: 0.4,
    EvidenceType.FIRST_SEEN: 0.3,
    EvidenceType.LAST_SEEN: 0.3,
    EvidenceType.TAG: 0.3,
    EvidenceType.OTHER: 0.3,
}

_DEFAULT_DIMENSION = EvidenceDimension.CAPABILITY

EVIDENCE_DIMENSION: dict[EvidenceType, EvidenceDimension] = {
    EvidenceType.BLOCKLIST: EvidenceDimension.REPUTATION,
    EvidenceType.DETECTION: EvidenceDimension.REPUTATION,
    EvidenceType.ABUSE_CONFIDENCE: EvidenceDimension.REPUTATION,
    EvidenceType.MALWARE_FAMILY: EvidenceDimension.CAPABILITY,
    EvidenceType.SANDBOX_OBSERVATION: EvidenceDimension.CAPABILITY,
    EvidenceType.PULSE_MATCH: EvidenceDimension.ATTRIBUTION,
    EvidenceType.COMMUNICATION: EvidenceDimension.INFRASTRUCTURE,
    EvidenceType.CLASSIFICATION: EvidenceDimension.WEAKNESS,
    EvidenceType.CATEGORY: EvidenceDimension.CAPABILITY,
    EvidenceType.FIRST_SEEN: EvidenceDimension.INFRASTRUCTURE,
    EvidenceType.LAST_SEEN: EvidenceDimension.INFRASTRUCTURE,
    EvidenceType.TAG: EvidenceDimension.ATTRIBUTION,
    EvidenceType.OTHER: EvidenceDimension.CAPABILITY,
}

# Evidence types that argue an entity is significant/malicious (supporting);
# everything else is neutral context until a finding rule says otherwise (3.1b).
_SUPPORTING_TYPES = frozenset(
    {
        EvidenceType.BLOCKLIST,
        EvidenceType.DETECTION,
        EvidenceType.ABUSE_CONFIDENCE,
        EvidenceType.MALWARE_FAMILY,
        EvidenceType.SANDBOX_OBSERVATION,
        EvidenceType.PULSE_MATCH,
    }
)


def base_weight(evidence_type: EvidenceType) -> float:
    """Static base weight for an evidence type."""
    return EVIDENCE_BASE_WEIGHT.get(evidence_type, _DEFAULT_BASE_WEIGHT)


def dimension_for(evidence_type: EvidenceType) -> EvidenceDimension:
    """The closed-enum dimension for an evidence type."""
    return EVIDENCE_DIMENSION.get(evidence_type, _DEFAULT_DIMENSION)


def polarity_for(evidence_type: EvidenceType) -> EvidencePolarity:
    """Default polarity for an evidence type (reputation handled separately)."""
    if evidence_type in _SUPPORTING_TYPES:
        return EvidencePolarity.SUPPORTING
    return EvidencePolarity.CONTEXTUAL


# --------------------------------------------------------------------------- #
# Reputation lifting (provider Reputation → weighted evidence)
# --------------------------------------------------------------------------- #

# Strength of a reputation verdict as a signal (0..1), regardless of direction.
REPUTATION_WEIGHT: dict[ReputationLevel, float] = {
    ReputationLevel.MALICIOUS: 1.0,
    ReputationLevel.LIKELY_MALICIOUS: 0.8,
    ReputationLevel.SUSPICIOUS: 0.6,
    ReputationLevel.LIKELY_BENIGN: 0.5,
    ReputationLevel.BENIGN: 0.8,
}

REPUTATION_POLARITY: dict[ReputationLevel, EvidencePolarity] = {
    ReputationLevel.MALICIOUS: EvidencePolarity.SUPPORTING,
    ReputationLevel.LIKELY_MALICIOUS: EvidencePolarity.SUPPORTING,
    ReputationLevel.SUSPICIOUS: EvidencePolarity.SUPPORTING,
    ReputationLevel.LIKELY_BENIGN: EvidencePolarity.CONTRADICTING,
    ReputationLevel.BENIGN: EvidencePolarity.CONTRADICTING,
}


# --------------------------------------------------------------------------- #
# Freshness decay
# --------------------------------------------------------------------------- #

_FRESH_FULL = timedelta(days=30)  # full weight within 30 days
_FRESH_ZERO = timedelta(days=365)  # decayed to the floor by a year
_FRESH_FLOOR = 0.3


def freshness(observed_at: datetime | None, now: datetime) -> float:
    """Recency multiplier in ``[_FRESH_FLOOR, 1.0]``.

    Timeless or undated evidence (e.g. knowledge facts) returns 1.0 — it is never
    penalised. Dated evidence decays linearly from full (≤30d) to the floor (≥1y).
    """
    if observed_at is None:
        return 1.0
    oa = observed_at if observed_at.tzinfo else observed_at.replace(tzinfo=UTC)
    ref = now if now.tzinfo else now.replace(tzinfo=UTC)
    age = ref - oa
    if age <= _FRESH_FULL:
        return 1.0
    if age >= _FRESH_ZERO:
        return _FRESH_FLOOR
    span = (_FRESH_ZERO - _FRESH_FULL).total_seconds()
    over = (age - _FRESH_FULL).total_seconds()
    return 1.0 - (1.0 - _FRESH_FLOOR) * (over / span)
