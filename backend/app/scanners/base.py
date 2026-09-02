"""The scanner contract.

Every scanner implements this interface and emits the same record type. This is
the seam that makes the unified inventory structural rather than cosmetic: the
risk engine and the correlation engine only ever see ``RawFinding`` and cannot
tell which scanner produced one.

That is also what allows a fourth scanner, for binaries or for a running
process, to be added later without the scoring engine changing at all.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator
from dataclasses import dataclass

from app.models.schemas import RawFinding


class ScanError(RuntimeError):
    """Raised when a target is malformed, unreachable or unauthorised."""


@dataclass
class ScanJob:
    """One unit of scanning work handed to a scanner."""

    scan_id: int
    target: str
    authorized: bool = False
    fixture: bool = False


class Scanner(abc.ABC):
    """Base class for every discovery source."""

    #: One of "code", "tls" or "certificate".
    kind: str = "unknown"

    @abc.abstractmethod
    def validate(self, job: ScanJob) -> None:
        """Raise :class:`ScanError` if the target cannot or must not be scanned.

        Called before any work begins, and for network scanners before any
        socket is opened.
        """

    @abc.abstractmethod
    def run(self, job: ScanJob) -> Iterator[RawFinding]:
        """Yield findings.

        Implementations stream rather than building a full list, so memory
        stays flat on a large target.
        """

    def fixture_findings(self, job: ScanJob) -> Iterator[RawFinding]:
        """Canned results used when a scanner is unavailable.

        Fixture mode exists so a demonstration survives a broken dependency.
        Scans run this way are flagged in the database and labelled in the
        interface, so fixture output can never be mistaken for a live scan.
        """
        return iter(())
