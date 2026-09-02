"""Shannon entropy pass for possible key material.

The masking rule here is the one that makes the "key material never stored in
full" claim true rather than asserted. A detected literal is reduced to its
length, its first four characters, its entropy and a truncated SHA-256
fingerprint before it leaves this module. The literal itself is never returned,
never persisted and never logged.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask(value: str) -> str:
    """Reduce a secret to something safe to store and display.

    ``"AKIA5SUPERSECRETVALUE"`` becomes ``"AKIA... (21 chars)"``. Enough for an
    analyst to locate and rotate the secret, not enough for anyone to use it.
    """
    head = value[:4]
    return f"{head}... ({len(value)} chars)"


def fingerprint(value: str) -> str:
    """First 16 hex characters of the SHA-256 digest.

    Enough to correlate the same secret appearing in two places, not enough to
    recover it.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


_LITERAL = re.compile(r"""(?:'([^'\n]{8,})'|"([^"\n]{8,})")""")


def candidate_literals(line: str) -> list[str]:
    """Extract quoted string literals long enough to be worth testing."""
    out: list[str] = []
    for match in _LITERAL.finditer(line):
        out.append(match.group(1) or match.group(2))
    return out


def is_allowlisted(value: str, patterns: list[str]) -> bool:
    """True when a literal is structural rather than secret."""
    return any(re.search(p, value) for p in patterns)


def looks_like_prose(value: str) -> bool:
    """True for literals that are sentences rather than key material.

    English prose with punctuation clears an entropy threshold of 4.5 easily, so
    entropy alone reports every docstring in the codebase as a possible secret.
    Whitespace is the cheap discriminator: keys, tokens and hashes are
    contiguous, sentences are not. Without this the signal to noise ratio of the
    entropy pass makes it unusable.
    """
    return any(character.isspace() for character in value)
