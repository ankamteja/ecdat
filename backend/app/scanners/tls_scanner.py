"""TLS endpoint discovery.

Enumerates which protocol versions a host accepts and which cipher suite it
negotiates, then reports the certificate it presents.

**Authorisation.** ``validate`` refuses an unauthorised job before any socket is
opened. The caller is responsible for writing the audit record first; see
``app.api.v1.scans``. The ordering is the control: an audit entry written after
a scan records only the scans that finished, while one written before records
every scan that was attempted.

Scope: SSLyze is the production choice and is named in the design documents.
The prototype uses the standard library ``ssl`` module so the tool installs
cleanly anywhere Python runs, which matters more for a demonstration than
cipher enumeration depth.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterator
from typing import Optional
from urllib.parse import urlparse

from app.knowledge.loader import load
from app.models.schemas import RawFinding
from app.scanners.base import Scanner, ScanError, ScanJob

# Protocol versions probed, newest first, mapped to the knowledge base names.
_PROTOCOLS: list[tuple[str, int]] = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
]

_CONNECT_TIMEOUT = 6.0

#: Weak cipher suites probed for explicitly, each mapped to its algorithm row.
#:
#: Reporting only the suite a server happens to negotiate understates its
#: exposure: a server that prefers AES-256 but still accepts 3DES is
#: vulnerable to a downgrade, and the negotiated-suite view would never show
#: it. Each of these is offered on its own, so acceptance is proven rather
#: than inferred.
_WEAK_CIPHERS: list[tuple[str, str]] = [
    ("DES-CBC3-SHA", "3DES"),
    ("ECDHE-RSA-DES-CBC3-SHA", "3DES"),
    ("RC4-MD5", "RC4"),
    ("RC4-SHA", "RC4"),
    ("DES-CBC-SHA", "DES"),
    ("AES128-SHA", "AES-128"),
]


class TlsScanner(Scanner):
    """Probes one host and port."""

    kind = "tls"

    def __init__(self) -> None:
        """Hold a reference to the cached knowledge base."""
        self.kb = load()

    # ---------------------------------------------------------------- validate

    def validate(self, job: ScanJob) -> None:
        """Refuse the scan unless it is explicitly authorised, before any socket.

        This runs before :meth:`run` and therefore before any network activity.
        The caller is separately responsible for writing the audit record first;
        see :func:`app.api.v1.scans.create_scan`.

        Raises:
            ScanError: if authorisation was not asserted, or the target cannot
                be parsed into a host and a valid port.
        """
        if not job.authorized:
            raise ScanError(
                "A network scan requires explicit authorisation. "
                "Resubmit with authorized set to true."
            )
        host, port = parse_target(job.target)
        if not host:
            raise ScanError(f"Cannot parse a host from target: {job.target}")
        if not (0 < port < 65536):
            raise ScanError(f"Port out of range: {port}")

    # --------------------------------------------------------------------- run

    def run(self, job: ScanJob) -> Iterator[RawFinding]:
        """Probe the endpoint and report what it accepts.

        Each protocol version is offered on its own, then the weak cipher pass
        runs. Reporting only what a server negotiates would understate its
        exposure, because a server that prefers a strong suite can still accept
        a broken one.

        Raises:
            ScanError: if no handshake succeeded at any protocol version, which
                means the endpoint is unreachable rather than secure.
        """
        if job.fixture:
            yield from self.fixture_findings(job)
            return

        host, port = parse_target(job.target)
        locator = f"{host}:{port}"
        exposure = "internet" if not _is_private(host) else "internal"
        reachable = False

        for name, version in _PROTOCOLS:
            result = self._probe(host, port, version)
            if result is None:
                continue
            reachable = True
            cipher_name, _, _ = result

            yield RawFinding(
                rule_id="ECDAT-TLS-PROTO",
                algorithm=name,
                locator=locator,
                asset_kind="tls",
                primitive="protocol",
                context="security",
                exposure=exposure,
                evidence_masked=f"{name} accepted, negotiated {cipher_name}",
                confidence=0.95,
                asset_meta={"analysis": "tls-handshake", "host": host, "port": port},
            )

            cipher_finding = self._cipher_finding(cipher_name, locator, exposure)
            if cipher_finding:
                yield cipher_finding

        if not reachable:
            raise ScanError(f"No TLS handshake succeeded against {locator}")

        yield from self._weak_cipher_pass(host, port, locator, exposure)

    def _weak_cipher_pass(
        self, host: str, port: int, locator: str, exposure: str
    ) -> Iterator[RawFinding]:
        """Offer each weak suite alone and report the ones the server accepts.

        This is what separates "which cipher did we get" from "which ciphers
        would this server agree to". A server that prefers a strong suite can
        still accept a broken one, and only the second question describes the
        actual exposure.
        """
        seen: set[str] = set()
        untestable: list[str] = []

        for suite, algorithm in _WEAK_CIPHERS:
            if algorithm in seen:
                continue
            supported, accepted = self._probe_cipher(host, port, suite)
            if not supported:
                untestable.append(suite)
                continue
            if not accepted:
                continue
            seen.add(algorithm)
            yield RawFinding(
                rule_id="ECDAT-TLS-WEAK-CIPHER",
                algorithm=algorithm,
                locator=locator,
                asset_kind="tls",
                primitive=self.kb.algorithm(algorithm).primitive,
                context="security",
                exposure=exposure,
                evidence_masked=f"accepts weak cipher suite {suite}",
                confidence=0.95,
                asset_meta={"analysis": "tls-cipher-probe", "cipher_suite": suite},
            )

        if untestable:
            # Reported explicitly rather than silently omitted. A user who sees
            # no RC4 finding would otherwise conclude the server rejects RC4,
            # when in fact the question was never asked. A false negative that
            # looks like a clean result is the worst failure mode a security
            # scanner has, so the gap is stated as a finding.
            yield RawFinding(
                rule_id="ECDAT-TLS-UNTESTABLE",
                algorithm="REQUIRES-MANUAL-REVIEW",
                locator=locator,
                asset_kind="tls",
                primitive="protocol",
                context="security",
                exposure=exposure,
                evidence_masked=(
                    "Could not test " + ", ".join(untestable) + ". The local OpenSSL "
                    "build has removed these suites, so this endpoint was not checked "
                    "for them. Absence of a finding is not evidence of absence."
                ),
                # Below the manual review floor by design: this can never be
                # escalated, because it reports the absence of information.
                confidence=0.60,
                asset_meta={"analysis": "tls-cipher-probe", "untestable": untestable},
            )

    def _probe_cipher(self, host: str, port: int, suite: str) -> tuple[bool, bool]:
        """Offer ``suite`` alone.

        Returns ``(supported_locally, accepted_by_server)``. The first element
        distinguishes "the server refused" from "we could not ask", which are
        very different results and must not be collapsed into one boolean.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers(f"{suite}:@SECLEVEL=0")
        except (ssl.SSLError, ValueError):
            # Modern OpenSSL removes 3DES and RC4 outright. SSLyze bundles its
            # own OpenSSL fork for exactly this reason; adopting it is roadmap.
            return False, False
        try:
            with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host):
                    return True, True
        except (OSError, ssl.SSLError):
            return True, False

    # ------------------------------------------------------------------ probes

    def _probe(self, host: str, port: int, version: int) -> Optional[tuple[str, str, int]]:
        """Attempt one handshake pinned to a single protocol version."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
            # Older protocol versions need the legacy suites enabled to probe at all.
            context.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            return None

        try:
            with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cipher = tls.cipher()
                    return cipher if cipher else ("unknown", "", 0)
        except (OSError, ssl.SSLError):
            return None

    def _cipher_finding(self, cipher_name: str, locator: str, exposure: str) -> Optional[RawFinding]:
        """Map a negotiated cipher suite name onto a knowledge base algorithm."""
        upper = cipher_name.upper()
        algorithm = None
        if "RC4" in upper:
            algorithm = "RC4"
        elif "3DES" in upper or "DES-CBC3" in upper:
            algorithm = "3DES"
        elif "DES" in upper:
            algorithm = "DES"
        elif "AES_128" in upper or "AES128" in upper:
            algorithm = "AES-128"
        elif "AES_256" in upper or "AES256" in upper:
            algorithm = "AES-256"
        elif "CHACHA20" in upper:
            algorithm = "ChaCha20-Poly1305"

        if algorithm is None:
            return None

        return RawFinding(
            rule_id="ECDAT-TLS-CIPHER",
            algorithm=algorithm,
            locator=locator,
            asset_kind="tls",
            primitive=self.kb.algorithm(algorithm).primitive,
            context="security",
            exposure=exposure,
            evidence_masked=f"negotiated {cipher_name}",
            confidence=0.95,
            asset_meta={"analysis": "tls-handshake", "cipher_suite": cipher_name},
        )

    # ------------------------------------------------------------- fixtures

    def fixture_findings(self, job: ScanJob) -> Iterator[RawFinding]:
        """Canned TLS finding, labelled as fixture output."""
        host, port = parse_target(job.target)
        locator = f"{host}:{port}"
        yield RawFinding(
            rule_id="ECDAT-TLS-PROTO",
            algorithm="TLSv1.0",
            locator=locator,
            asset_kind="tls",
            primitive="protocol",
            exposure="internal",
            evidence_masked="TLSv1.0 accepted (fixture)",
            confidence=0.95,
            asset_meta={"analysis": "fixture"},
        )


def parse_target(target: str) -> tuple[str, int]:
    """Split ``host:port``, ``https://host`` or a bare host into host and port."""
    value = target.strip()
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or "", parsed.port or 443
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, 443
    return value, 443


def _is_private(host: str) -> bool:
    """Best effort check so exposure weighting reflects reachability."""
    import ipaddress

    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False
