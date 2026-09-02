"""ORM tables.

Two properties here are load bearing and are enforced by structure rather than
by convention:

1. ``AuditLog`` has no update or delete path anywhere in the application. The
   append only guarantee is enforced by the absence of code, not by a rule
   somebody has to remember.
2. ``Finding`` stores ``classical_score`` and ``quantum_score`` separately and
   permanently. A consumer that wants one number can compute it; a consumer
   that only stored a blend could never recover the distinction, and that
   distinction is the entire point of the tool.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def _utcnow() -> dt.datetime:
    """Timezone-aware UTC now.

    Used as a column default rather than ``datetime.utcnow``, which returns a
    naive value and silently compares wrong against aware timestamps.
    """
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    """An operator account.

    The prototype seeds exactly one administrator at startup. Passwords are
    stored as bcrypt hashes of a SHA-256 pre-digest; see
    :mod:`app.core.security` for why the pre-digest is necessary.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="admin")


class Scan(Base):
    """One scan job against one target."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # code | tls | certificate
    target: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    authorized_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fixture_mode: Mapped[bool] = mapped_column(default=False)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    """A scanned thing: a source file, a host and port, or a certificate."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    locator: Mapped[str] = mapped_column(String(512), index=True)
    meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="assets")


class Finding(Base):
    """One cryptographic observation, already scored."""

    __tablename__ = "findings"
    # Unique per scan, not globally. A dedupe key identifies "the same finding",
    # so re-scanning an unchanged target legitimately reproduces every key it
    # produced last time. A global constraint would make the second scan of any
    # target fail, and re-scanning is the normal case rather than the exception.
    __table_args__ = (UniqueConstraint("scan_id", "dedupe_key", name="uq_findings_scan_dedupe"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    algorithm: Mapped[str] = mapped_column(String(64), index=True)
    primitive: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mode: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    padding: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    curve: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    context: Mapped[str] = mapped_column(String(32), default="security")
    exposure: Mapped[str] = mapped_column(String(32), default="internal")
    file_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    line_no: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Masked evidence only. The literal never reaches this column. See scanners.secrets.
    evidence_masked: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    entropy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    confidence: Mapped[float] = mapped_column(Float, default=0.85)
    classical_score: Mapped[float] = mapped_column(Float, default=0.0)
    quantum_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), index=True, default="LOW")
    pqc_vulnerable: Mapped[bool] = mapped_column(default=False, index=True)
    capped_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    nist_deprecated_after: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    nist_disallowed_after: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    standard_refs: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), index=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Correlation(Base):
    """A link ECDAT drew between two assets, usually across two sources."""

    __tablename__ = "correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    asset_a: Mapped[str] = mapped_column(String(512))
    asset_b: Mapped[str] = mapped_column(String(512))
    relation: Mapped[str] = mapped_column(String(64))
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Report(Base):
    """A generated report file.

    The SHA-256 digest is recorded so a report handed to a third party can be
    shown to be the one this scan produced, unmodified.
    """

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    format: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class AuditLog(Base):
    """Append only. There is deliberately no update or delete path to this table."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(512))
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
