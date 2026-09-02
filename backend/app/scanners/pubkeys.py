"""Public key material embedded in source files.

This is what makes cross source correlation possible. A certificate scanned
from a file and a public key pinned inside a repository are the same key, but
only if both are reduced to the same identifier. Both this module and the
certificate scanner fingerprint the SubjectPublicKeyInfo structure with
SHA-256 and keep the first sixteen hex characters, so the two views join.

Without this the correlation engine has nothing to join on, and the claim that
ECDAT links code to certificates would be architecture with no evidence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_PEM_BLOCK = re.compile(
    r"-----BEGIN (CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY)-----.*?"
    r"-----END (?:CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY)-----",
    re.DOTALL,
)


@dataclass
class EmbeddedKey:
    """A public key found inside a source file."""

    algorithm: str
    key_size: Optional[int]
    fingerprint: str
    line_no: int
    kind: str


def spki_fingerprint(public_key) -> str:
    """Stable identifier for a public key.

    Must stay identical to the certificate scanner's calculation, or the two
    sources will never correlate.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def find_embedded_keys(text: str) -> list[EmbeddedKey]:
    """Extract every parseable PEM public key or certificate from a file."""
    found: list[EmbeddedKey] = []
    for match in _PEM_BLOCK.finditer(text):
        block = match.group(0)
        line_no = text[: match.start()].count("\n") + 1
        parsed = _parse(block)
        if parsed is None:
            continue
        public_key, kind = parsed
        algorithm, key_size = _describe(public_key)
        if algorithm is None:
            continue
        found.append(
            EmbeddedKey(
                algorithm=algorithm,
                key_size=key_size,
                fingerprint=spki_fingerprint(public_key),
                line_no=line_no,
                kind=kind,
            )
        )
    return found


def _parse(block: str):
    """Load one PEM block, trying certificate then bare public key.

    Returns:
        A ``(public_key, kind)`` pair, or None if the block is not key material
        this build can read. Returning None rather than raising means one
        malformed block does not stop the file being scanned.
    """
    data = block.encode("utf-8")
    try:
        return x509.load_pem_x509_certificate(data).public_key(), "certificate"
    except Exception:  # noqa: BLE001 - try the next encoding
        pass
    try:
        return serialization.load_pem_public_key(data), "public-key"
    except Exception:  # noqa: BLE001 - not key material we can read
        return None


def _describe(public_key) -> tuple[Optional[str], Optional[int]]:
    """Map a public key object to an algorithm name and size.

    Returns ``(None, None)`` for an unrecognised key type, which is reported as
    no finding rather than as an unknown algorithm.
    """
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.curve.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    return None, None
