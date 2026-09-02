"""Golden cases that pin the scoring model.

These are the tests that matter most. The scoring model is the project's
original contribution, and every assertion here encodes a decision that was
argued for in the design documents. If one of these changes, the model changed,
and that should be deliberate rather than accidental.
"""

from __future__ import annotations

import pytest

from app.engine.risk import RiskEngine, dedupe_key
from app.models.schemas import RawFinding


@pytest.fixture(scope="module")
def engine() -> RiskEngine:
    """A risk engine bound to the production knowledge base.

    Deliberately not a stub. These tests assert the behaviour of the real
    scoring policy, so a change to the YAML must be able to fail them.
    """
    return RiskEngine()


def finding(**overrides) -> RawFinding:
    """Build a finding with sensible defaults, overriding only what matters.

    Keeps each test to the one or two fields it is actually about, so the
    assertion is not buried in boilerplate.
    """
    base = dict(rule_id="ECDAT-TEST", algorithm="MD5", locator="x.py", asset_kind="code")
    base.update(overrides)
    return RawFinding(**base)


# --------------------------------------------------------------- context

def test_md5_in_a_security_context_is_critical(engine):
    """A collision-broken hash used for security is the worst case.

    Pairs with the test below: same algorithm, different location, different
    severity.
    """
    score = engine.score(finding(algorithm="MD5", context="security"))
    assert score.severity == "CRITICAL"
    assert score.capped_by == "broken-algorithm:MD5"


def test_the_same_md5_call_in_a_test_directory_is_low(engine):
    """The identical call, scored differently by context.

    This is the difference between an inventory and an alert storm, and it is
    the concrete form of the CWSS environmental metric group.
    """
    score = engine.score(finding(algorithm="MD5", context="test"))
    assert score.severity == "LOW"


def test_non_security_usage_is_downweighted(engine):
    """A checksum is not a vulnerability, but it is not nothing either."""
    assert engine.score(finding(algorithm="MD5", context="non_security")).severity == "MEDIUM"


# --------------------------------------------------------------- dual axis

def test_rsa_2048_is_classically_acceptable_and_quantum_critical(engine):
    """The finding the whole project exists to surface.

    Classically fine, quantum fatal. If these two numbers were ever averaged
    this would score as unremarkable, which is the failure mode being avoided.
    """
    score = engine.score(finding(algorithm="RSA", key_size=2048))
    assert score.classical < 4.0, "RSA-2048 is not a classical problem today"
    assert score.quantum >= 9.0, "RSA-2048 is broken by Shor"
    assert score.severity == "CRITICAL"
    assert score.pqc_vulnerable is True
    assert score.disallowed_after == 2035


def test_the_two_axes_are_never_averaged(engine):
    """An average of 3.0 and 9.5 would be 6.25, which bands as MEDIUM."""
    score = engine.score(finding(algorithm="RSA", key_size=2048))
    average = (score.classical + score.quantum) / 2
    assert 4.0 <= average < 7.0, "guard: the average really would band lower"
    assert score.severity == "CRITICAL", "severity must follow the maximum, not the mean"


def test_undersized_rsa_is_also_a_classical_problem(engine):
    """RSA-1024 is breakable today, not only after a quantum computer.

    The parameter penalty is what separates it from RSA-2048, which is
    classically fine.
    """
    score = engine.score(finding(algorithm="RSA", key_size=1024))
    assert score.classical >= 9.0
    assert score.severity == "CRITICAL"


def test_strong_modern_crypto_is_low_on_both_axes(engine):
    """A correct modern choice must not generate noise.

    A scanner that flags AES-256 produces a report nobody reads.
    """
    score = engine.score(finding(algorithm="AES-256"))
    assert score.classical == 0.0
    assert score.quantum <= 1.0
    assert score.severity == "LOW"
    assert score.pqc_vulnerable is False


# ------------------------------------------------------- shor versus grover

def test_grover_affected_algorithms_are_not_migration_candidates(engine):
    """AES-128 and MD5 face Grover, not Shor.

    Grover halves a security margin and is fixed by a larger key. Shor breaks
    an algorithm outright and is fixed only by migration. Counting both as
    quantum vulnerable would put every MD5 finding on the PQC migration list
    and make the readiness percentage meaningless.
    """
    assert engine.score(finding(algorithm="AES-128")).pqc_vulnerable is False
    assert engine.score(finding(algorithm="MD5")).pqc_vulnerable is False


def test_shor_affected_algorithms_are_migration_candidates(engine):
    """Every public key algorithm Shor breaks must appear on the migration list."""
    for algorithm in ("RSA", "ECDSA", "ECDH", "DH", "DSA"):
        assert engine.score(finding(algorithm=algorithm)).pqc_vulnerable is True, algorithm


def test_post_quantum_algorithms_score_clean(engine):
    """The recommended replacements must not themselves be flagged."""
    for algorithm in ("ML-KEM", "ML-DSA", "SLH-DSA"):
        score = engine.score(finding(algorithm=algorithm))
        assert score.severity == "LOW"
        assert score.pqc_vulnerable is False


# --------------------------------------------------------------- exposure

def test_internet_exposure_raises_the_score(engine):
    """Reachability is part of risk: the same weakness matters more when exposed."""
    internal = engine.score(finding(algorithm="TLSv1.0", exposure="internal"))
    external = engine.score(finding(algorithm="TLSv1.0", exposure="internet"))
    assert external.classical > internal.classical


def test_scores_stay_clamped_to_ten(engine):
    """Exposure weighting multiplies by 1.15 and must not push a score past the band."""
    score = engine.score(finding(algorithm="MD5", exposure="internet"))
    assert score.classical <= 10.0 and score.quantum <= 10.0


# --------------------------------------------------------------- countdown

def test_years_remaining_counts_down_to_the_nist_deadline(engine):
    """The countdown is computed from today, not hardcoded.

    Written against the current year so it stays correct as time passes rather
    than silently asserting a stale number.
    """
    import datetime as dt

    score = engine.score(finding(algorithm="RSA", key_size=2048))
    assert score.years_remaining == 2035 - dt.date.today().year


def test_findings_without_a_deadline_report_none(engine):
    """An algorithm NIST has not scheduled must not invent an urgency."""
    assert engine.score(finding(algorithm="AES-256")).years_remaining is None


# --------------------------------------------------------------- dedupe

def test_dedupe_key_is_stable_across_runs(engine):
    """Re-scanning an unchanged target must reproduce the same inventory."""
    a, b = finding(line_no=12), finding(line_no=12)
    assert dedupe_key(a) == dedupe_key(b)


def test_dedupe_key_separates_different_locations(engine):
    """Two occurrences of the same weakness are two findings, not one."""
    assert dedupe_key(finding(line_no=12)) != dedupe_key(finding(line_no=13))
