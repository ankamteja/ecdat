"""Loads the YAML knowledge base and exposes it as typed objects.

The knowledge base is deliberately data rather than code. Changing a severity
threshold, adding an algorithm or tuning a weight is an edit to a YAML file in
this directory, never a change to scanner or engine logic. That separation is
borrowed from IBM CBOMkit, which keeps detection, enrichment and policy
evaluation independently replaceable.

Everything is cached at import time. The files are small and are not expected
to change while the process is running.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from app.core.config import settings

# Human readable expansions for the reference keys used in algorithms.yaml.
REFERENCE_TITLES: dict[str, str] = {
    "FIPS197": "FIPS 197, Advanced Encryption Standard",
    "FIPS180-4": "FIPS 180-4, Secure Hash Standard",
    "FIPS203": "FIPS 203, ML-KEM",
    "FIPS204": "FIPS 204, ML-DSA",
    "FIPS205": "FIPS 205, SLH-DSA",
    "SP800-131A": "NIST SP 800-131A Rev 2, Cryptographic Transitions",
    "IR8547": "NIST IR 8547 ipd, Transition to Post-Quantum Cryptography Standards",
    "RFC5280": "RFC 5280, X.509 Certificate Profile",
    "RFC7465": "RFC 7465, Prohibiting RC4 in TLS",
    "RFC8996": "RFC 8996, Deprecating TLS 1.0 and 1.1",
    "WANG2004": "Wang et al. 2004, Practical MD5 collision",
    "SHATTERED2017": "SHAttered 2017, SHA-1 collision",
    "SWEET32": "SWEET32 2016, CVE-2016-2183",
    "SHOR1994": "Shor 1994, polynomial time factoring",
    "GROVER1996": "Grover 1996, quadratic search speedup",
    "OWASP-A02": "OWASP Top 10 A02, Cryptographic Failures",
    "CWE-295": "CWE-295, Improper Certificate Validation",
}


@dataclass(frozen=True)
class AlgorithmEntry:
    """One row of the algorithm knowledge base."""

    name: str
    base_classical: float
    base_quantum: float
    primitive: Optional[str] = None
    status: str = "unknown"
    quantum_threat: str = "none"
    cwe: Optional[str] = None
    refs: tuple[str, ...] = ()
    deprecated_after: Optional[int] = None
    disallowed_after: Optional[int] = None
    note: Optional[str] = None

    @property
    def is_quantum_vulnerable(self) -> bool:
        """True only for Shor vulnerable algorithms.

        This is deliberately narrower than "has a non zero quantum score".
        Grover halves the security margin of AES-128 and SHA-256, which is a
        key size problem solved by using AES-256. Shor breaks RSA and elliptic
        curve outright, which is a migration problem solved only by moving to
        ML-KEM or ML-DSA.

        Counting both as "quantum vulnerable" would put every MD5 finding on
        the PQC migration list and make the readiness percentage meaningless.
        """
        return self.quantum_threat == "shor"

    @property
    def reference_titles(self) -> list[str]:
        """Human-readable titles for this algorithm's references.

        An unrecognised key is passed through unchanged rather than dropped, so
        adding a reference to the YAML without updating the title map degrades
        to showing the key instead of showing nothing.
        """
        return [REFERENCE_TITLES.get(r, r) for r in self.refs]


@dataclass(frozen=True)
class Rule:
    """One detection rule, compiled and ready to run against a source line."""

    id: str
    name: str
    algorithm: str
    group: str
    confidence: float
    langs: tuple[str, ...]
    compiled: tuple[re.Pattern, ...] = ()
    key_size_from_match: bool = False
    entropy_rule: bool = False
    note: Optional[str] = None


@dataclass(frozen=True)
class Policy:
    """Weights, bands and cap rules. The tunable part of the scoring model."""

    context_weights: dict[str, float]
    exposure_weights: dict[str, float]
    bands: dict[str, float]
    critical_algorithms: tuple[str, ...]
    critical_rules: tuple[str, ...]
    min_confidence_for_critical: float


@dataclass(frozen=True)
class Migration:
    """One row of the migration table: what to replace, and with what."""

    source: str
    usage: str
    target: str
    standard: str


@dataclass
class KnowledgeBase:
    """Everything the scoring model reads, parsed and ready to query.

    Built once by :func:`load` and cached. Treat it as read-only; the scanners
    and the risk engine share a single instance.
    """

    algorithms: dict[str, AlgorithmEntry]
    defaults: AlgorithmEntry
    rules: list[Rule]
    policy: Policy
    migrations: list[Migration]
    entropy: dict[str, Any] = field(default_factory=dict)

    def algorithm(self, name: str) -> AlgorithmEntry:
        """Look up an algorithm, falling back to the documented default row."""
        return self.algorithms.get(name, self.defaults)

    def migrations_for(self, algorithm: str) -> list[Migration]:
        """Every published replacement for an algorithm.

        An algorithm may have several, differing by usage: RSA maps to ML-KEM
        for key establishment and to ML-DSA for signatures.
        """
        return [m for m in self.migrations if m.source == algorithm]


def _read(name: str) -> dict:
    """Parse one YAML file from the knowledge directory."""
    with open(settings.knowledge_dir / name, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@functools.lru_cache(maxsize=1)
def load() -> KnowledgeBase:
    """Parse every knowledge file once and cache the result."""
    algo_doc = _read("algorithms.yaml")
    rules_doc = _read("rules.yaml")
    pqc_doc = _read("pqc_map.yaml")
    entropy_doc = _read("entropy.yaml")

    algorithms: dict[str, AlgorithmEntry] = {}
    for name, row in algo_doc["algorithms"].items():
        algorithms[name] = AlgorithmEntry(
            name=name,
            base_classical=float(row.get("base_classical", 0.0)),
            base_quantum=float(row.get("base_quantum", 0.0)),
            primitive=row.get("primitive"),
            status=row.get("status", "unknown"),
            quantum_threat=row.get("quantum_threat", "none"),
            cwe=row.get("cwe"),
            refs=tuple(row.get("refs", ())),
            deprecated_after=row.get("deprecated_after"),
            disallowed_after=row.get("disallowed_after"),
            note=row.get("note"),
        )

    d = algo_doc["defaults"]
    defaults = AlgorithmEntry(
        name="UNKNOWN",
        base_classical=float(d["base_classical"]),
        base_quantum=float(d["base_quantum"]),
        cwe=d.get("cwe"),
    )

    rules: list[Rule] = []
    for row in rules_doc["rules"]:
        rules.append(
            Rule(
                id=row["id"],
                name=row["name"],
                algorithm=row["algorithm"],
                group=row["group"],
                confidence=float(row["confidence"]),
                langs=tuple(row.get("langs", ())),
                compiled=tuple(re.compile(p) for p in row.get("patterns", [])),
                key_size_from_match=bool(row.get("key_size_from_match", False)),
                entropy_rule=bool(row.get("entropy_rule", False)),
                note=row.get("note"),
            )
        )

    caps = algo_doc["caps"]
    policy = Policy(
        context_weights=algo_doc["weights"]["context"],
        exposure_weights=algo_doc["weights"]["exposure"],
        bands=algo_doc["bands"],
        critical_algorithms=tuple(caps["critical_algorithms"]),
        critical_rules=tuple(caps["critical_rules"]),
        min_confidence_for_critical=float(caps["min_confidence_for_critical"]),
    )

    migrations = [
        Migration(source=m["from"], usage=m["usage"], target=m["to"], standard=m["standard"])
        for m in pqc_doc["migrations"]
    ]

    return KnowledgeBase(
        algorithms=algorithms,
        defaults=defaults,
        rules=rules,
        policy=policy,
        migrations=migrations,
        entropy=entropy_doc["entropy"],
    )
