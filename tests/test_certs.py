"""Certificate analysis against the generated sample set."""

from __future__ import annotations

import pytest

from app.scanners import CertScanner
from app.scanners.base import ScanJob


@pytest.fixture(scope="module")
def findings(samples_dir):
    """Every finding from a scan of the bundled sample certificate set."""
    scanner = CertScanner()
    job = ScanJob(scan_id=1, target=str(samples_dir / "certs"))
    scanner.validate(job)
    return list(scanner.run(job))


def by_file(findings, fragment):
    """Filter findings down to one certificate file by name fragment."""
    return [f for f in findings if fragment in (f.file_path or "")]


def test_sha1_signature_is_detected(findings):
    """The deliberately weak sample's signature algorithm is caught."""
    weak = by_file(findings, "weak-sha1")
    assert any(f.algorithm == "SHA-1" and f.rule_id == "ECDAT-CERT-SIG" for f in weak)


def test_undersized_rsa_key_is_detected(findings):
    """The 1024 bit key ships with a key size, not just an algorithm name."""
    weak = by_file(findings, "weak-sha1")
    keys = [f for f in weak if f.rule_id == "ECDAT-CERT-KEY"]
    assert keys and keys[0].algorithm == "RSA" and keys[0].key_size == 1024


def test_expired_certificate_is_flagged(findings):
    """Lifecycle findings do not depend on the signature or key being weak."""
    assert any(f.rule_id == "ECDAT-CERT-EXPIRED" for f in by_file(findings, "weak-sha1"))


def test_missing_san_is_flagged(findings):
    """An RFC 5280 profile violation is reported even on an otherwise valid cert."""
    assert any(f.rule_id == "ECDAT-CERT-NO-SAN" for f in by_file(findings, "ec-no-san"))


def test_over_long_validity_is_flagged(findings):
    """Validity exceeding the CA/Browser Forum 398 day baseline is caught."""
    assert any(f.rule_id == "ECDAT-CERT-LONG-VALIDITY" for f in by_file(findings, "ec-no-san"))


def test_self_signed_certificates_are_flagged(findings):
    """A self-signed certificate is flagged regardless of the rest of its profile."""
    assert any(f.rule_id == "ECDAT-CERT-SELF-SIGNED" for f in findings)


def test_signature_and_key_are_reported_separately(findings):
    """They carry different risk profiles and must not be collapsed.

    A SHA-1 signature is forgeable today. An RSA-2048 key is fine today and
    disallowed after 2035. One certificate, two very different findings.
    """
    modern = by_file(findings, "modern-rsa2048")
    rules = {f.rule_id for f in modern}
    assert {"ECDAT-CERT-SIG", "ECDAT-CERT-KEY"} <= rules

    signature = next(f for f in modern if f.rule_id == "ECDAT-CERT-SIG")
    key = next(f for f in modern if f.rule_id == "ECDAT-CERT-KEY")
    assert signature.algorithm == "SHA-256"
    assert key.algorithm == "RSA" and key.key_size == 2048


def test_certificate_keys_carry_a_correlatable_fingerprint(findings):
    """Without a fingerprint the correlation engine has nothing to join on."""
    keys = [f for f in findings if f.rule_id == "ECDAT-CERT-KEY"]
    assert keys and all(f.fingerprint for f in keys)
