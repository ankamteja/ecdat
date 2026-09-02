"""Test fixtures. MD5 here is a cache key, not a security control.

ECDAT should score this LOW because of the test directory context weight and
the non security usage, while scoring the identical call in auth_service.py as
CRITICAL. That difference is the point of the context weighting.
"""

import hashlib


def cache_key(name: str) -> str:
    return hashlib.md5(name.encode()).hexdigest()
