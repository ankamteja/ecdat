"""X.509 certificate discovery.

Parses PEM and DER certificates with the PyCA ``cryptography`` library and
reports both the signature algorithm and the public key algorithm, which are
two distinct findings with two distinct risk profiles:

* The signature algorithm is a classical concern. A SHA-1 signature is
  forgeable today.
* The public key algorithm is the quantum concern. An RSA-2048 key is fine
  today and disallowed by NIST after 2035.

Reporting them separately is what lets the same certificate appear as LOW on
one axis and CRITICAL on the other, which is the behaviour the dual axis model
exists to produce.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.knowledge.loader import load
from app.models.schemas import RawFinding
from app.scanners.base import Scanner, ScanError, ScanJob

# Signature hash names as reported by cryptography, mapped to knowledge base rows.
_HASH_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}

_EXPIRY_WARNING_DAYS = 30
_MAX_VALIDITY_DAYS = 398  # CA/Browser Forum baseline


class CertScanner(Scanner):
    """Reads one certificate file or a directory of them."""

    kind = "certificate"

    def __init__(self) -> None:
        """Hold a reference to the cached knowledge base."""
        self.kb = load()

    # ---------------------------------------------------------------- validate

    def validate(self, job: ScanJob) -> None:
        """Confirm the certificate file or directory exists.

        Raises:
            ScanError: if the path is missing.
        """
        path = Path(job.target).expanduser()
        if not path.exists():
            raise ScanError(f"Certificate path does not exist: {job.target}")

    # --------------------------------------------------------------------- run

    def run(self, job: ScanJob) -> Iterator[RawFinding]:
        """Parse every certificate under the target and yield its findings.

        Accepts a single file or a directory, and reads both PEM and DER.
        Unparseable files are skipped rather than failing the scan, so one
        corrupt certificate in a store does not hide the rest.

        Raises:
            ScanError: if no certificate files are found at all, which usually
                means the target path is wrong.
        """
        if job.fixture:
            yield from self.fixture_findings(job)
            return

        path = Path(job.target).expanduser().resolve()
        files = [path] if path.is_file() else sorted(
            p for p in path.rglob("*") if p.suffix.lower() in {".pem", ".crt", ".cer", ".der"}
        )
        if not files:
            raise ScanError(f"No certificate files found under {path}")

        for file_path in files:
            cert = _load_certificate(file_path)
            if cert is None:
                continue
            yield from self._analyse(cert, file_path.name)

    # ---------------------------------------------------------------- analysis

    def _analyse(self, cert: x509.Certificate, name: str) -> Iterator[RawFinding]:
        """Produce every finding for one certificate.

        Emits the signature algorithm and the public key algorithm as separate
        findings, then any lifecycle and profile flags. The separation matters:
        the two carry different risk profiles and collapsing them would hide
        one behind the other.
        """
        subject = _common_name(cert.subject) or name
        locator = f"cert:{subject}"
        meta = self._metadata(cert, name, subject)

        # 1. Signature algorithm, the classical concern.
        hash_name = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown")
        algorithm = _HASH_NAMES.get(hash_name.lower(), hash_name.upper())
        yield RawFinding(
            rule_id="ECDAT-CERT-SIG",
            algorithm=algorithm,
            locator=locator,
            asset_kind="certificate",
            primitive="hash",
            context="security",
            exposure="internal",
            file_path=name,
            evidence_masked=f"signature algorithm {hash_name}",
            confidence=0.95,
            asset_meta=meta,
        )

        # 2. Public key algorithm, the quantum concern.
        key_algorithm, key_size, curve = _public_key_info(cert)
        if key_algorithm:
            yield RawFinding(
                rule_id="ECDAT-CERT-KEY",
                algorithm=key_algorithm,
                locator=locator,
                asset_kind="certificate",
                primitive=self.kb.algorithm(key_algorithm).primitive,
                key_size=key_size,
                curve=curve,
                context="security",
                exposure="internal",
                file_path=name,
                # The public key fingerprint is what the correlation engine
                # joins on to link this certificate to code and to endpoints.
                fingerprint=meta.get("spki_sha256"),
                evidence_masked=f"{key_algorithm} public key, {key_size or curve or 'unknown'}",
                confidence=0.95,
                asset_meta=meta,
            )

        # 3. Lifecycle and profile flags.
        for finding in self._flag_findings(cert, locator, name, meta):
            yield finding

    def _flag_findings(
        self, cert: x509.Certificate, locator: str, name: str, meta: dict
    ) -> Iterator[RawFinding]:
        """Report lifecycle and RFC 5280 profile problems.

        Covers expiry, imminent expiry, over-long validity against the
        CA/Browser Forum baseline, self-signing, and a missing subject
        alternative name.
        """
        now = dt.datetime.now(dt.timezone.utc)
        not_after = _not_after(cert)
        not_before = _not_before(cert)

        if not_after < now:
            yield self._flag(locator, name, meta, "ECDAT-CERT-EXPIRED", f"expired on {not_after.date()}")
        elif (not_after - now).days <= _EXPIRY_WARNING_DAYS:
            yield self._flag(
                locator, name, meta, "ECDAT-CERT-EXPIRING",
                f"expires in {(not_after - now).days} days", confidence=0.90,
            )

        if (not_after - not_before).days > _MAX_VALIDITY_DAYS:
            yield self._flag(
                locator, name, meta, "ECDAT-CERT-LONG-VALIDITY",
                f"validity {(not_after - not_before).days} days exceeds 398", confidence=0.90,
            )

        if cert.issuer == cert.subject:
            yield self._flag(
                locator, name, meta, "ECDAT-CERT-SELF-SIGNED", "self signed", confidence=0.95,
            )

        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            yield self._flag(
                locator, name, meta, "ECDAT-CERT-NO-SAN",
                "no subject alternative name, RFC 5280 profile violation", confidence=0.90,
            )

    def _flag(
        self, locator: str, name: str, meta: dict, rule_id: str, message: str, confidence: float = 0.95
    ) -> RawFinding:
        """Lifecycle findings carry no algorithm, so they score on context alone."""
        return RawFinding(
            rule_id=rule_id,
            algorithm="CERT-LIFECYCLE",
            locator=locator,
            asset_kind="certificate",
            primitive="certificate",
            context="security",
            exposure="internal",
            file_path=name,
            evidence_masked=message,
            confidence=confidence,
            asset_meta=meta,
        )

    def _metadata(self, cert: x509.Certificate, name: str, subject: str) -> dict:
        """Build the descriptive metadata attached to every finding.

        Includes ``spki_sha256``, the public key fingerprint the correlation
        engine joins on to link this certificate to code and to endpoints.
        """
        # Shared with the code scanner's embedded key pass. The two must stay
        # identical or a key in a repository will never correlate to the
        # certificate that carries it.
        from app.scanners.pubkeys import spki_fingerprint

        return {
            "file": name,
            "subject": subject,
            "issuer": _common_name(cert.issuer) or "unknown",
            "serial": str(cert.serial_number),
            "not_before": _not_before(cert).isoformat(),
            "not_after": _not_after(cert).isoformat(),
            "spki_sha256": spki_fingerprint(cert.public_key()),
        }

    # ------------------------------------------------------------- fixtures

    def fixture_findings(self, job: ScanJob) -> Iterator[RawFinding]:
        """Canned certificate finding, labelled as fixture output."""
        yield RawFinding(
            rule_id="ECDAT-CERT-SIG",
            algorithm="SHA-1",
            locator="cert:fixture.example",
            asset_kind="certificate",
            primitive="hash",
            evidence_masked="signature algorithm sha1 (fixture)",
            confidence=0.95,
            asset_meta={"analysis": "fixture"},
        )


# --------------------------------------------------------------------- helpers


def _load_certificate(path: Path) -> Optional[x509.Certificate]:
    """Read a certificate, trying PEM then DER.

    Returns None rather than raising, so an unreadable file is skipped instead
    of aborting a scan over a directory of otherwise valid certificates.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            return loader(data)
        except Exception:  # noqa: BLE001 - try the next encoding
            continue
    return None


def _common_name(name: x509.Name) -> Optional[str]:
    """Extract the common name from a subject or issuer, if present."""
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else None


def _public_key_info(cert: x509.Certificate) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Identify the public key algorithm, size and curve.

    Returns:
        A ``(algorithm, key_size, curve)`` triple. All three are None for a key
        type this build does not recognise, which is reported as no key finding
        rather than as a guess.
    """
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA", key.curve.key_size, key.curve.name
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "ed25519"
    return None, None, None


def _aware(value: dt.datetime) -> dt.datetime:
    """Normalise to timezone aware UTC."""
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _not_before(cert: x509.Certificate) -> dt.datetime:
    """Validity start, across cryptography versions.

    The ``*_utc`` properties arrived in cryptography 42. Older releases expose
    naive datetimes under the unsuffixed names, so both are supported.
    """
    value = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    return _aware(value)


def _not_after(cert: x509.Certificate) -> dt.datetime:
    """Validity end, across cryptography versions."""
    value = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return _aware(value)
