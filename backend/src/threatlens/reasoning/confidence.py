"""The ConfidenceScorer — deterministic, explainable, four factors.

Given a group of :class:`WeightedEvidence`, produces a :class:`Confidence`
(numeric score + band + per-factor breakdown). The four factors are exactly the
approved set — Authority, Agreement, Corroboration, Freshness. There is no
relationship-strength factor, and asset criticality, EPSS, and KEV are
structurally excluded: this function's only inputs are the evidence and the
reference time. It is pure and never uses AI.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from . import config
from .models import (
    Confidence,
    ConfidenceBand,
    ConfidenceFactor,
    EvidencePolarity,
    WeightedEvidence,
)

# Approved factor weights (sum to 1.0). Do not tune beyond the architecture.
_W_AUTHORITY = 0.35
_W_AGREEMENT = 0.25
_W_CORROBORATION = 0.25
_W_FRESHNESS = 0.15

# Bands by score; ascending so a "contested" cap can clamp downward.
_BAND_ORDER = (
    ConfidenceBand.INSUFFICIENT,
    ConfidenceBand.LOW,
    ConfidenceBand.MODERATE,
    ConfidenceBand.HIGH,
    ConfidenceBand.VERY_HIGH,
)
_CONTESTED_RATIO = 0.25  # contradiction share that flags a finding as contested
_AUTHORITATIVE = 0.9  # authority at/above which an authoritative fact ignores the cap


class ConfidenceScorer:
    """Computes a deterministic confidence from a group of weighted evidence."""

    def score(self, evidence: Sequence[WeightedEvidence], *, now: datetime) -> Confidence:
        """Score the confidence that the supporting evidence is correct."""
        supporting = [we for we in evidence if we.polarity is EvidencePolarity.SUPPORTING]
        contradicting = [we for we in evidence if we.polarity is EvidencePolarity.CONTRADICTING]

        if not supporting:
            # Nothing asserts the claim — confidence is not assessable.
            return Confidence(
                score=0,
                band=ConfidenceBand.INSUFFICIENT,
                contested=bool(contradicting),
                factors=[
                    ConfidenceFactor(
                        name="insufficient",
                        contribution=0,
                        detail="no supporting evidence",
                    )
                ],
            )

        support_weight = sum(we.weight for we in supporting)
        contradict_weight = sum(we.weight for we in contradicting)
        total_weight = support_weight + contradict_weight

        authority = max(config.max_authority(we.evidence.sources) for we in supporting)
        agreement = support_weight / total_weight if total_weight > 0 else 1.0
        family_set: set[str] = set()
        for we in supporting:
            family_set |= config.families(we.evidence.sources)
        # Diminishing returns by *family* (not raw provider count): a single
        # family gives no corroboration; each additional independent family adds
        # less. Echo-chamber feeds collapse into one family and earn nothing.
        corroboration = 1.0 - 1.0 / len(family_set)
        fresh = max(config.freshness(we.evidence.evidence.observed_at, now) for we in supporting)

        score = round(
            100.0
            * (
                _W_AUTHORITY * authority
                + _W_AGREEMENT * agreement
                + _W_CORROBORATION * corroboration
                + _W_FRESHNESS * fresh
            )
        )
        score = max(0, min(100, score))

        contested = contradict_weight > 0 and (contradict_weight / total_weight) >= _CONTESTED_RATIO
        band = self._band(score, contested=contested, authority=authority)

        factors = [
            ConfidenceFactor(
                name="authority",
                contribution=round(100 * _W_AUTHORITY * authority),
                detail=f"max supporting source authority {authority:.2f}",
            ),
            ConfidenceFactor(
                name="agreement",
                contribution=round(100 * _W_AGREEMENT * agreement),
                detail=(f"support {support_weight:.2f} vs contradiction {contradict_weight:.2f}"),
            ),
            ConfidenceFactor(
                name="corroboration",
                contribution=round(100 * _W_CORROBORATION * corroboration),
                detail=f"{len(family_set)} independent authority family(ies)",
            ),
            ConfidenceFactor(
                name="freshness",
                contribution=round(100 * _W_FRESHNESS * fresh),
                detail=f"freshest supporting evidence {fresh:.2f}",
            ),
        ]
        return Confidence(score=score, band=band, contested=contested, factors=factors)

    @staticmethod
    def _band(score: int, *, contested: bool, authority: float) -> ConfidenceBand:
        if score < 10:
            return ConfidenceBand.INSUFFICIENT
        if score < 30:
            band = ConfidenceBand.LOW
        elif score < 60:
            band = ConfidenceBand.MODERATE
        elif score < 85:
            band = ConfidenceBand.HIGH
        else:
            band = ConfidenceBand.VERY_HIGH

        # Contested findings are capped at MODERATE unless carried by an
        # authoritative fact (which surfaces despite the contradiction).
        if contested and authority < _AUTHORITATIVE:
            capped_index = min(_BAND_ORDER.index(band), _BAND_ORDER.index(ConfidenceBand.MODERATE))
            band = _BAND_ORDER[capped_index]
        return band
