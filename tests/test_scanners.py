"""Scanner behaviour against the deliberately vulnerable sample."""

from __future__ import annotations

import pytest

from app.scanners import CodeScanner
from app.scanners.base import ScanJob
from app.scanners.secrets import looks_like_prose, mask, shannon_entropy


@pytest.fixture(scope="module")
def findings(samples_dir):
    """Every finding from a scan of the bundled vulnerable sample repository."""
    scanner = CodeScanner()
    job = ScanJob(scan_id=1, target=str(samples_dir / "vulnerable-repo"))
    scanner.validate(job)
    return list(scanner.run(job))


def test_the_sample_yields_a_useful_number_of_findings(findings):
    """A floor, not an exact count, so an added rule does not break this test."""
    assert len(findings) >= 15


def test_all_three_languages_are_covered(findings):
    """Python, Java and JavaScript each produce at least one finding."""
    suffixes = {f.file_path.rsplit(".", 1)[-1] for f in findings if f.file_path}
    assert {"py", "java", "js"} <= suffixes


def test_the_expected_weak_algorithms_are_found(findings):
    """A spot check across categories: broken hashes, a broken cipher, ECB, and a secret."""
    algorithms = {f.algorithm for f in findings}
    for expected in ("MD5", "SHA-1", "DES", "ECB", "HARDCODED-SECRET"):
        assert expected in algorithms, expected


def test_the_python_ast_pass_runs_and_is_labelled(findings):
    """The AST pass produces output, and only ever on .py files."""
    ast_findings = [f for f in findings if f.asset_meta.get("analysis") == "python-ast"]
    assert ast_findings, "the AST pass produced nothing"
    assert all(f.file_path.endswith(".py") for f in ast_findings)


def test_every_finding_records_which_pass_produced_it(findings):
    """No report may overstate the analysis method used."""
    assert all(f.asset_meta.get("analysis") for f in findings)


def test_test_directories_are_scored_as_test_context(findings):
    """The tests/ directory inside the scan target resolves to test context."""
    in_tests = [f for f in findings if f.file_path and "tests/" in f.file_path]
    assert in_tests, "the sample test directory produced no findings"
    assert all(f.context == "test" for f in in_tests)


def test_secret_literals_never_appear_in_output(findings, samples_dir):
    """The key material claim, asserted rather than trusted."""
    planted = "Zk4Qm8Xr2TyUz1Vn7Wk3Pl6Ab5Cd0Eg9Hj7Ns"
    source = (samples_dir / "vulnerable-repo" / "auth_service.py").read_text()
    assert planted in source, "guard: the planted secret is still in the sample"

    for finding in findings:
        assert planted not in (finding.evidence_masked or "")
        assert planted not in str(finding.asset_meta)


def test_secrets_are_reported_with_enough_detail_to_rotate(findings):
    """A masked secret still carries enough metadata for an analyst to act on it."""
    secrets = [f for f in findings if f.rule_id == "ECDAT-018"]
    assert secrets
    for finding in secrets:
        assert finding.fingerprint and finding.entropy
        assert finding.file_path and finding.line_no


def test_embedded_public_keys_are_fingerprinted(findings):
    """Without this the cross source correlation has nothing to join on."""
    embedded = [f for f in findings if f.rule_id == "ECDAT-EMBEDDED-KEY"]
    assert embedded, "the pinned key in the sample was not detected"
    assert all(f.fingerprint for f in embedded)


# ------------------------------------------------------------ secret helpers

def test_prose_is_not_mistaken_for_key_material():
    """English text clears an entropy threshold of 4.5, so length alone is not enough."""
    assert looks_like_prose("Practical MD5 collision attack, Wang et al. 2004")
    assert not looks_like_prose("Zk4Qm8Xr2TyUz1Vn7Wk3Pl6Ab5Cd0Eg")


def test_mask_reveals_a_prefix_and_a_length_only():
    """The masking function itself, isolated from the scanner that calls it."""
    masked = mask("SUPERSECRETVALUE12345")
    assert masked.startswith("SUPE") and "21 chars" in masked
    assert "SECRETVALUE" not in masked


def test_entropy_separates_random_from_repetitive():
    """Sanity check on the entropy function before trusting it to classify secrets."""
    assert shannon_entropy("aB3xK9mQ7pL2vN8wR4tY6uZ1") > 4.0
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 1.0


def test_context_is_judged_inside_the_scan_target_not_the_absolute_path(samples_dir, tmp_path):
    """A repository living under a path containing "samples" or "test" must not
    have every finding downweighted.

    Regression test. The scanner originally classified context from the
    absolute path, so scanning samples/vulnerable-repo marked every finding as
    test context because an ancestor directory was called "samples". The
    findings still appeared, just at the wrong severity, which is the kind of
    bug that survives a green test suite and only shows up in the dashboard.
    """
    scanner = CodeScanner()
    job = ScanJob(scan_id=1, target=str(samples_dir / "vulnerable-repo"))
    findings = list(scanner.run(job))

    service = [f for f in findings if f.file_path == "auth_service.py"]
    assert service, "the sample service file produced no findings"
    assert all(f.context == "security" for f in service), (
        "findings in the scanned service were misclassified as test context"
    )

    in_tests = [f for f in findings if f.file_path and f.file_path.startswith("tests/")]
    assert in_tests and all(f.context == "test" for f in in_tests), (
        "a tests/ directory inside the scan target must still count as test context"
    )


def test_the_same_call_scores_differently_by_location(samples_dir):
    """The behaviour the product claim rests on, asserted end to end.

    hashlib.md5 in the service is CRITICAL. The identical call in tests/ is LOW.
    """
    from app.engine.risk import RiskEngine

    engine = RiskEngine()
    scanner = CodeScanner()
    findings = list(scanner.run(ScanJob(scan_id=1, target=str(samples_dir / "vulnerable-repo"))))

    service_md5 = [f for f in findings if f.algorithm == "MD5" and f.file_path == "auth_service.py"]
    test_md5 = [f for f in findings if f.algorithm == "MD5" and (f.file_path or "").startswith("tests/")]
    assert service_md5 and test_md5

    assert engine.score(service_md5[0]).severity == "CRITICAL"
    assert engine.score(test_md5[0]).severity == "LOW"


def test_untestable_cipher_suites_are_reported_not_silently_dropped():
    """A coverage gap must be visible in the inventory.

    Modern OpenSSL removes 3DES and RC4 from the client, so those suites cannot
    be probed at all. Silently omitting them would show a user no RC4 finding
    and let them conclude the server rejects RC4, when the question was never
    asked. A false negative that looks like a clean result is the worst failure
    mode a security scanner has, so the gap is emitted as a finding below the
    manual review confidence floor, where it can never be escalated.
    """
    import ssl

    from app.scanners.tls_scanner import _WEAK_CIPHERS, TlsScanner

    scanner = TlsScanner()
    removed = []
    for suite, _ in _WEAK_CIPHERS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            context.set_ciphers(f"{suite}:@SECLEVEL=0")
        except (ssl.SSLError, ValueError):
            removed.append(suite)

    for suite in removed:
        supported, accepted = scanner._probe_cipher("127.0.0.1", 1, suite)
        assert supported is False, f"{suite} should report as locally unsupported"
        assert accepted is False

    # A suite the local build still offers must report as supported, so that
    # "server refused" is never confused with "we could not ask".
    supported, _ = scanner._probe_cipher("127.0.0.1", 1, "AES128-SHA")
    assert supported is True
