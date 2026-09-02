"""Sample authentication service with deliberate cryptographic flaws."""

import hashlib
import random
import ssl

import requests
from cryptography.hazmat.primitives.asymmetric import rsa

# ECDAT-017: hardcoded secret literal
API_SECRET = "Zk4Qm8Xr2TyUz1Vn7Wk3Pl6Ab5Cd0Eg9Hj7Ns"
DB_PASSWORD = "hunter2-not-a-real-password"


def hash_password(password: str) -> str:
    """ECDAT-001: MD5 is collision broken (Wang 2004)."""
    return hashlib.md5(password.encode()).hexdigest()


def legacy_digest(payload: bytes) -> str:
    """ECDAT-002: SHA-1 is collision broken (SHAttered 2017)."""
    return hashlib.sha1(payload).hexdigest()


def generate_session_token() -> str:
    """ECDAT-011: predictable RNG used for a security token."""
    token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return token


def make_keypair():
    """ECDAT-006: RSA below the 2048 bit floor in SP 800-131A."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def fetch_profile(url: str):
    """ECDAT-014: certificate verification disabled."""
    return requests.get(url, verify=False)


def legacy_tls_context():
    """ECDAT-013: pinned to a protocol deprecated by RFC 8996."""
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
