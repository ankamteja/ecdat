"""Pydantic request and response models.

``RawFinding`` is the important one. It is the single record type every scanner
emits, and it is deliberately source agnostic: the risk engine cannot tell
whether a finding came from a file, a socket or a certificate. That is what
allows a fourth scanner to be added later without the engine changing.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

ScanKind = Literal["code", "tls", "certificate"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Context = Literal["security", "non_security", "test"]
Exposure = Literal["internet", "internal", "sample"]


class RawFinding(BaseModel):
    """Source agnostic observation produced by a scanner, before scoring."""

    rule_id: str
    algorithm: str
    locator: str
    asset_kind: ScanKind
    primitive: Optional[str] = None
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    context: Context = "security"
    exposure: Exposure = "internal"
    file_path: Optional[str] = None
    line_no: Optional[int] = None
    evidence_masked: Optional[str] = None
    entropy: Optional[float] = None
    fingerprint: Optional[str] = None
    confidence: float = 0.85
    asset_meta: dict[str, Any] = Field(default_factory=dict)


class ScanCreate(BaseModel):
    """A request to start a scan.

    ``authorized`` is required for a TLS scan and is refused with 403 without
    it. It is a deliberate assertion by the caller that they are permitted to
    probe the target, not a checkbox the client can default to true, and the
    refusal is written to the audit log either way.

    ``fixture`` returns canned findings instead of scanning. It exists so a
    demonstration survives a broken dependency, and it is recorded on the scan
    and labelled in the interface so fixture output can never be mistaken for a
    live result.
    """

    kind: ScanKind
    target: str
    authorized: bool = False
    fixture: bool = False


class ScanOut(BaseModel):
    """A scan as returned by the API, including its progress and result count."""

    id: int
    kind: str
    target: str
    status: str
    fixture_mode: bool
    authorized_by: Optional[str]
    started_at: dt.datetime
    finished_at: Optional[dt.datetime]
    duration_ms: Optional[int]
    error: Optional[str]
    finding_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class FindingOut(BaseModel):
    """One scored finding.

    Both axes are present and are never merged into a single number. A consumer
    that wants one score can compute it; a consumer given only a blend could
    never recover the distinction between "weak today" and "broken by a quantum
    computer", which is the distinction the tool exists to surface.

    ``evidence_masked`` is safe to display. Detected key material is reduced to
    a prefix and a length before it reaches this field.
    """

    id: int
    rule_id: str
    algorithm: str
    primitive: Optional[str]
    key_size: Optional[int]
    context: str
    exposure: str
    file_path: Optional[str]
    line_no: Optional[int]
    evidence_masked: Optional[str]
    confidence: float
    classical_score: float
    quantum_score: float
    severity: str
    pqc_vulnerable: bool
    capped_by: Optional[str]
    nist_deprecated_after: Optional[int]
    nist_disallowed_after: Optional[int]
    standard_refs: Optional[str]
    cwe: Optional[str]
    locator: str = ""

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    """A bearer token issued on successful login."""

    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    """Credentials for :func:`app.api.v1.auth.login`."""

    username: str
    password: str
