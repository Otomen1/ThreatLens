"""Tests for the ConfidenceScorer (Phase 3.1a).

The scorer is deterministic and uses exactly four factors (authority, agreement,
corroboration, freshness). Its only inputs are the weighted evidence and the
reference time — asset criticality, EPSS and KEV are structurally excluded.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from threatlens.providers.aggregation import AttributedEvidence
from threatlens.providers.results import Evidence, EvidenceType
from threatlens.reasoning import (
    ConfidenceBand,
    ConfidenceScorer,
    EvidenceDimension,
    EvidencePolarity,
    WeightedEvidence,
)

NOW = datetime(2024, 6, 1, tzinfo=UTC)


def _we(
    polarity: EvidencePolarity,
    *,
    weight: float = 1.0,
    sources: list[str] | None = None,
    observed_at: datetime | None = None,
    dimension: EvidenceDimension = EvidenceDimension.REPUTATION,
) -> WeightedEvidence:
    return WeightedEvidence(
        evidence=AttributedEvidence(
            evidence=Evidence(type=EvidenceType.OTHER, summary="s", observed_at=observed_at),
            sources=sources or ["abuseipdb"],
        ),
        weight=weight,
        polarity=polarity,
        dimension=dimension,
    )


def _score(evidence: list[WeightedEvidence]):
    return ConfidenceScorer().score(evidence, now=NOW)


# --------------------------------------------------------------------------- #
# Insufficient / empty
# --------------------------------------------------------------------------- #


class TestInsufficient:
    def test_empty_is_insufficient(self) -> None:
        c = _score([])
        assert c.band is ConfidenceBand.INSUFFICIENT
        assert c.score == 0

    def test_only_contextual_is_insufficient(self) -> None:
        c = _score([_we(EvidencePolarity.CONTEXTUAL), _we(EvidencePolarity.CONTEXTUAL)])
        assert c.band is ConfidenceBand.INSUFFICIENT

    def test_only_contradicting_is_insufficient(self) -> None:
        c = _score([_we(EvidencePolarity.CONTRADICTING)])
        assert c.band is ConfidenceBand.INSUFFICIENT
        assert c.contested is True


# --------------------------------------------------------------------------- #
# Factors & bands
# --------------------------------------------------------------------------- #


class TestFactorsAndBands:
    def test_factor_breakdown_present(self) -> None:
        c = _score([_we(EvidencePolarity.SUPPORTING, sources=["nvd"])])
        names = {f.name for f in c.factors}
        assert names == {"authority", "agreement", "corroboration", "freshness"}

    def test_single_authoritative_source_is_high_not_very_high(self) -> None:
        # One family → zero corroboration caps a lone source below VERY_HIGH.
        c = _score([_we(EvidencePolarity.SUPPORTING, sources=["nvd"])])
        assert c.band is ConfidenceBand.HIGH

    def test_two_families_reach_very_high(self) -> None:
        c = _score(
            [
                _we(EvidencePolarity.SUPPORTING, sources=["nvd"]),
                _we(EvidencePolarity.SUPPORTING, sources=["otx"]),
            ]
        )
        assert c.band is ConfidenceBand.VERY_HIGH

    def test_single_weak_source_is_moderate(self) -> None:
        c = _score([_we(EvidencePolarity.SUPPORTING, sources=["mystery"])])
        assert c.band is ConfidenceBand.MODERATE

    def test_higher_authority_raises_score(self) -> None:
        weak = _score([_we(EvidencePolarity.SUPPORTING, sources=["mystery"])])
        strong = _score([_we(EvidencePolarity.SUPPORTING, sources=["nvd"])])
        assert strong.score > weak.score


# --------------------------------------------------------------------------- #
# Echo-chamber / corroboration by family
# --------------------------------------------------------------------------- #


class TestCorroboration:
    def test_same_family_does_not_corroborate(self) -> None:
        # urlhaus + malwarebazaar share the abuse.ch family → one family.
        same = _score(
            [
                _we(EvidencePolarity.SUPPORTING, sources=["urlhaus"]),
                _we(EvidencePolarity.SUPPORTING, sources=["malwarebazaar"]),
            ]
        )
        distinct = _score(
            [
                _we(EvidencePolarity.SUPPORTING, sources=["urlhaus"]),
                _we(EvidencePolarity.SUPPORTING, sources=["abuseipdb"]),
            ]
        )
        same_corr = next(f.contribution for f in same.factors if f.name == "corroboration")
        distinct_corr = next(f.contribution for f in distinct.factors if f.name == "corroboration")
        assert same_corr == 0
        assert distinct_corr > same_corr


# --------------------------------------------------------------------------- #
# Freshness
# --------------------------------------------------------------------------- #


class TestFreshness:
    def test_stale_lowers_score(self) -> None:
        fresh = _score([_we(EvidencePolarity.SUPPORTING, sources=["nvd"], observed_at=NOW)])
        stale = _score(
            [
                _we(
                    EvidencePolarity.SUPPORTING,
                    sources=["nvd"],
                    observed_at=NOW - timedelta(days=400),
                )
            ]
        )
        assert stale.score < fresh.score


# --------------------------------------------------------------------------- #
# Contradiction / contested
# --------------------------------------------------------------------------- #


class TestContested:
    def test_contradiction_flags_contested_and_lowers_score(self) -> None:
        clean = _score([_we(EvidencePolarity.SUPPORTING, sources=["abuseipdb"])])
        contested = _score(
            [
                _we(EvidencePolarity.SUPPORTING, sources=["abuseipdb"], weight=1.0),
                _we(EvidencePolarity.CONTRADICTING, sources=["otx"], weight=1.0),
            ]
        )
        assert contested.contested is True
        assert contested.score < clean.score

    def test_contested_low_authority_capped_at_moderate(self) -> None:
        # Four distinct low-authority families would score HIGH (~64), but the
        # contradiction (contested) caps it at MODERATE because authority < 0.9.
        c = _score(
            [
                _we(EvidencePolarity.SUPPORTING, sources=["low1"], weight=1.0),
                _we(EvidencePolarity.SUPPORTING, sources=["low2"], weight=1.0),
                _we(EvidencePolarity.SUPPORTING, sources=["low3"], weight=1.0),
                _we(EvidencePolarity.SUPPORTING, sources=["low4"], weight=1.0),
                _we(EvidencePolarity.CONTRADICTING, sources=["low5"], weight=1.0),
                _we(EvidencePolarity.CONTRADICTING, sources=["low6"], weight=1.0),
            ]
        )
        assert c.contested is True
        assert c.band is ConfidenceBand.MODERATE

    def test_contested_authoritative_not_capped(self) -> None:
        # nvd authority ≥ 0.9 lets an authoritative fact exceed the contested cap.
        c = _score(
            [
                _we(EvidencePolarity.SUPPORTING, sources=["nvd"], weight=1.0),
                _we(EvidencePolarity.CONTRADICTING, sources=["mystery"], weight=0.5),
            ]
        )
        assert c.contested is True
        assert c.band is ConfidenceBand.HIGH


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


class TestDeterminism:
    def test_identical_inputs_identical_output(self) -> None:
        evidence = [
            _we(EvidencePolarity.SUPPORTING, sources=["nvd"]),
            _we(EvidencePolarity.SUPPORTING, sources=["otx"]),
            _we(EvidencePolarity.CONTRADICTING, sources=["mystery"]),
        ]
        assert ConfidenceScorer().score(evidence, now=NOW) == ConfidenceScorer().score(
            evidence, now=NOW
        )
