"""Cap rules and the confidence floor.

Cap rules exist because some cryptographic defects are disqualifying no matter
where they appear, and a weighted average must not be allowed to argue them
down. Adapted from the SSL Labs pattern where one defect caps the grade.
"""

from __future__ import annotations

import pytest

from app.engine.risk import RiskEngine
from app.models.schemas import RawFinding


@pytest.fixture(scope="module")
def engine() -> RiskEngine:
    """A risk engine bound to the production knowledge base and its cap rules."""
    return RiskEngine()


def finding(**overrides) -> RawFinding:
    """Build a finding with sensible defaults, overriding only what matters."""
    base = dict(rule_id="ECDAT-TEST", algorithm="MD5", locator="x.py", asset_kind="code")
    base.update(overrides)
    return RawFinding(**base)


def test_hardcoded_key_is_critical_regardless_of_context(engine):
    """A cap rule must override the context weight, not be overridden by it."""
    score = engine.score(
        finding(algorithm="HARDCODED-SECRET", rule_id="ECDAT-017", context="non_security")
    )
    assert score.severity == "CRITICAL"
    assert score.capped_by is not None


def test_disabled_certificate_verification_is_critical(engine):
    """A verification bypass is disqualifying wherever it appears."""
    score = engine.score(finding(algorithm="CERT-VERIFY-DISABLED", rule_id="ECDAT-014"))
    assert score.severity == "CRITICAL"


def test_a_clean_asset_cannot_be_inflated_above_low(engine):
    """The inverse cap. Weighting must not manufacture a warning."""
    score = engine.score(finding(algorithm="ML-KEM", exposure="internet"))
    assert score.severity == "LOW"
    assert score.capped_by == "clean-asset-floor"


def test_low_confidence_findings_are_demoted_not_escalated(engine):
    """Below the confidence floor a finding is reported, never escalated.

    This is the concrete form of "requires manual review" and it is the honest
    answer to cryptography the tool cannot resolve.
    """
    score = engine.score(
        finding(algorithm="HARDCODED-SECRET", rule_id="ECDAT-018", confidence=0.50)
    )
    assert score.requires_manual_review is True
    assert score.severity == "HIGH", "must be demoted from CRITICAL"
    assert score.capped_by == "confidence-below-threshold"


def test_findings_at_the_confidence_floor_may_still_be_critical(engine):
    """Exactly 0.70 is admitted; only strictly below it is demoted."""
    score = engine.score(
        finding(algorithm="HARDCODED-SECRET", rule_id="ECDAT-017", confidence=0.70)
    )
    assert score.severity == "CRITICAL"


def test_broken_algorithm_in_test_context_is_not_capped(engine):
    """A cap must not fire on something that is not actually a vulnerability."""
    score = engine.score(finding(algorithm="MD5", context="test"))
    assert score.capped_by is None
