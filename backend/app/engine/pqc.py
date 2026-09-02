"""Post quantum readiness.

Turns scored findings into the answer an organisation can act on: what fraction
of assets are clear, which algorithms have to move, what they move to, and how
long there is to do it.

The dates are not ours. NIST IR 8547 ipd (November 2024) deprecates quantum
vulnerable signature and key establishment algorithms at 112 bits of security
after 2030 and disallows them after 2035, and National Security Memorandum 10
sets 2035 as the national migration target.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Optional

from app.knowledge.loader import KnowledgeBase, load

#: The date every countdown is measured against.
NIST_DISALLOWED_YEAR = 2035
NIST_DEPRECATED_YEAR = 2030


@dataclass
class MigrationRow:
    """One line of the migration table shown on the readiness page."""

    algorithm: str
    asset_count: int
    finding_count: int
    target: str
    standard: str
    deprecated_after: Optional[int]
    disallowed_after: Optional[int]
    years_remaining: Optional[int]


@dataclass
class ReadinessReport:
    """Post-quantum readiness across a set of findings.

    ``readiness_percent`` counts assets with no Shor-vulnerable findings.
    Grover-affected primitives such as AES-128 are deliberately excluded: they
    are a key size problem, not a migration problem, and counting them would
    make the percentage meaningless.
    """

    total_assets: int
    ready_assets: int
    at_risk_assets: int
    readiness_percent: float
    migrations: list[MigrationRow] = field(default_factory=list)
    headline: str = ""


def assess(rows: list[dict], kb: Optional[KnowledgeBase] = None) -> ReadinessReport:
    """Compute readiness from scored finding rows.

    ``rows`` need ``locator``, ``algorithm`` and ``pqc_vulnerable``.
    """
    kb = kb or load()
    current_year = dt.date.today().year

    all_assets = {row["locator"] for row in rows}
    at_risk_assets = {row["locator"] for row in rows if row.get("pqc_vulnerable")}
    ready = len(all_assets) - len(at_risk_assets)
    percent = (ready / len(all_assets) * 100.0) if all_assets else 100.0

    grouped: dict[str, dict] = {}
    for row in rows:
        if not row.get("pqc_vulnerable"):
            continue
        algorithm = row["algorithm"]
        bucket = grouped.setdefault(algorithm, {"assets": set(), "findings": 0})
        bucket["assets"].add(row["locator"])
        bucket["findings"] += 1

    migrations: list[MigrationRow] = []
    for algorithm, bucket in sorted(grouped.items(), key=lambda kv: -len(kv[1]["assets"])):
        entry = kb.algorithm(algorithm)
        options = kb.migrations_for(algorithm)
        target = options[0].target if options else "ML-KEM or ML-DSA"
        standard = options[0].standard if options else "FIPS 203 / 204"
        disallowed = entry.disallowed_after or NIST_DISALLOWED_YEAR
        migrations.append(
            MigrationRow(
                algorithm=algorithm,
                asset_count=len(bucket["assets"]),
                finding_count=bucket["findings"],
                target=target,
                standard=standard,
                deprecated_after=entry.deprecated_after,
                disallowed_after=disallowed,
                years_remaining=max(0, disallowed - current_year),
            )
        )

    return ReadinessReport(
        total_assets=len(all_assets),
        ready_assets=ready,
        at_risk_assets=len(at_risk_assets),
        readiness_percent=round(percent, 1),
        migrations=migrations,
        headline=_headline(migrations),
    )


def _headline(migrations: list[MigrationRow]) -> str:
    """The single sentence the dashboard leads with.

    Deliberately concrete. "Quantum vulnerable" tells an organisation nothing
    it did not already know; a named algorithm, an asset count and a deadline
    is a migration plan.
    """
    if not migrations:
        return "No quantum vulnerable algorithms found. This scope is post-quantum ready."
    top = migrations[0]
    assets = "asset" if top.asset_count == 1 else "assets"
    return (
        f"{top.algorithm} found in {top.asset_count} {assets}. "
        f"Deprecated by NIST after {top.deprecated_after or NIST_DEPRECATED_YEAR}, "
        f"disallowed after {top.disallowed_after}. "
        f"{top.years_remaining} years remaining."
    )
