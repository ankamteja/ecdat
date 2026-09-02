"""Generate the deliberately weak certificate set used by tests and the demo.

Regenerate with:  python3 samples/certs/generate.py

These are throwaway keys for a sample. They protect nothing.
"""

from __future__ import annotations

import datetime as dt
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).parent


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ECDAT Sample"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _write(cert: x509.Certificate, filename: str) -> None:
    (HERE / filename).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"wrote {filename}")


def build(common_name: str, key, hash_alg, days_valid: int, start_offset: int, san: bool):
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))  # self signed on purpose
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + dt.timedelta(days=start_offset))
        .not_valid_after(now + dt.timedelta(days=start_offset + days_valid))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
    return builder.sign(key, hash_alg)


def build_sha1_via_openssl() -> None:
    """Generate the SHA-1 signed certificate with the openssl CLI.

    Recent releases of the cryptography library refuse to sign with SHA-1,
    which is correct behaviour and is exactly the weakness ECDAT reports. The
    sample still has to contain one, so it is produced out of process.
    """
    out = HERE / "weak-sha1-rsa1024.pem"
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "key.pem"
        subprocess.run(
            ["openssl", "genrsa", "-out", str(key), "1024"],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-x509", "-sha1",
                "-key", str(key), "-out", str(out),
                "-not_before", "20220101000000Z", "-not_after", "20230101000000Z",
                "-subj", "/C=IN/O=ECDAT Sample/CN=legacy.ecdat.sample",
            ],
            check=True, capture_output=True,
        )
    print("wrote weak-sha1-rsa1024.pem")


def main() -> None:
    # 1. SHA-1 signature, RSA-1024 key, expired. Should score CRITICAL twice over.
    build_sha1_via_openssl()

    # 2. Modern signature, RSA-2048 key. Classically fine, quantum vulnerable.
    ok_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write(build("api.ecdat.sample", ok_key, hashes.SHA256(), 90, 0, True), "modern-rsa2048.pem")

    # 3. EC key, no SAN, over long validity. RFC 5280 profile issues.
    ec_key = ec.generate_private_key(ec.SECP256R1())
    _write(build("ec.ecdat.sample", ec_key, hashes.SHA256(), 900, 0, False), "ec-no-san-long.pem")


if __name__ == "__main__":
    main()
