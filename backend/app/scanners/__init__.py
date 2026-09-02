"""Discovery sources.

Each scanner implements :class:`app.scanners.base.Scanner` and emits the same
source agnostic ``RawFinding``. Register a new source here and the API, the
risk engine and the correlation engine pick it up without modification.
"""

from app.scanners.base import Scanner, ScanError, ScanJob
from app.scanners.cert_scanner import CertScanner
from app.scanners.code_scanner import CodeScanner
from app.scanners.tls_scanner import TlsScanner

#: The scanner registry, keyed by scan kind.
SCANNERS: dict[str, type[Scanner]] = {
    CodeScanner.kind: CodeScanner,
    TlsScanner.kind: TlsScanner,
    CertScanner.kind: CertScanner,
}


def get_scanner(kind: str) -> Scanner:
    """Instantiate the scanner registered for ``kind``."""
    try:
        return SCANNERS[kind]()
    except KeyError as exc:
        raise ScanError(f"No scanner registered for kind: {kind}") from exc


__all__ = ["Scanner", "ScanError", "ScanJob", "SCANNERS", "get_scanner",
           "CodeScanner", "TlsScanner", "CertScanner"]
