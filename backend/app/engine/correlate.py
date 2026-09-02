"""Correlation: turning three sets of findings into one inventory.

This module is the product claim. Any tool can list weak algorithms found in
one place. What no tool in the comparison does is state that the RSA key in a
repository is the same key as the one in the certificate served by a host,
because no single tool sees both.

Two things happen here:

1. **Deduplication.** A stable key means re-scanning an unchanged target yields
   an identical inventory rather than a growing pile of duplicates.
2. **Cross source linking.** Findings from different scanners are joined on
   shared evidence, currently the public key fingerprint and the hostname.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from app.models.schemas import RawFinding
from app.engine.risk import dedupe_key


@dataclass
class Correlation:
    """A link between two assets, usually across two discovery sources."""

    asset_a: str
    asset_b: str
    relation: str
    note: str = ""


@dataclass
class InventoryCell:
    """One cell of the asset by algorithm matrix."""

    count: int = 0
    worst_severity: str = "LOW"
    pqc_vulnerable: bool = False


@dataclass
class Inventory:
    """The unified view: which assets use which algorithms."""

    assets: list[str] = field(default_factory=list)
    algorithms: list[str] = field(default_factory=list)
    cells: dict[str, dict[str, InventoryCell]] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)


_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def deduplicate(findings: Iterable[RawFinding]) -> list[RawFinding]:
    """Drop repeat observations of the same thing, keeping the first seen."""
    seen: set[str] = set()
    unique: list[RawFinding] = []
    for finding in findings:
        key = dedupe_key(finding)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def build_inventory(rows: list[dict]) -> Inventory:
    """Build the asset by algorithm matrix from scored finding rows.

    Each row needs ``locator``, ``algorithm``, ``severity``, ``pqc_vulnerable``
    and ``asset_kind``.
    """
    inventory = Inventory()
    cells: dict[str, dict[str, InventoryCell]] = defaultdict(dict)
    algorithms: set[str] = set()

    for row in rows:
        asset = row["locator"]
        algorithm = row["algorithm"]
        algorithms.add(algorithm)
        inventory.sources[asset] = row.get("asset_kind", "code")

        cell = cells[asset].get(algorithm) or InventoryCell()
        cell.count += 1
        if _SEVERITY_ORDER[row["severity"]] > _SEVERITY_ORDER[cell.worst_severity]:
            cell.worst_severity = row["severity"]
        cell.pqc_vulnerable = cell.pqc_vulnerable or bool(row.get("pqc_vulnerable"))
        cells[asset][algorithm] = cell

    inventory.assets = sorted(cells)
    inventory.algorithms = sorted(algorithms)
    inventory.cells = {a: dict(v) for a, v in cells.items()}
    return inventory


def correlate(rows: list[dict]) -> list[Correlation]:
    """Find relationships between assets discovered by different scanners.

    Currently two joins:

    * **Shared public key.** The same SPKI fingerprint appearing on more than
      one asset. This is what links a certificate to the endpoint serving it,
      and to a key committed in a repository.
    * **Hostname match.** A TLS endpoint whose host matches a certificate
      subject, which links the network view to the certificate view even when
      the key material was never seen directly.
    """
    links: list[Correlation] = []

    by_fingerprint: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        fingerprint = row.get("fingerprint")
        if fingerprint:
            by_fingerprint[fingerprint].add(row["locator"])

    for fingerprint, assets in by_fingerprint.items():
        if len(assets) < 2:
            continue
        ordered = sorted(assets)
        for i in range(len(ordered)):
            for j in range(i + 1, len(ordered)):
                links.append(
                    Correlation(
                        asset_a=ordered[i],
                        asset_b=ordered[j],
                        relation="shared-key-material",
                        note=f"Identical public key fingerprint {fingerprint}.",
                    )
                )

    hosts = {r["locator"].split(":")[0]: r["locator"] for r in rows if r.get("asset_kind") == "tls"}
    subjects = {
        r["locator"].removeprefix("cert:"): r["locator"]
        for r in rows
        if r.get("asset_kind") == "certificate"
    }
    for host, tls_locator in hosts.items():
        if host in subjects:
            links.append(
                Correlation(
                    asset_a=tls_locator,
                    asset_b=subjects[host],
                    relation="endpoint-presents-certificate",
                    note=f"Endpoint host matches certificate subject {host}.",
                )
            )

    return links
