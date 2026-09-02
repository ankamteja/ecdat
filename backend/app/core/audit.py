"""Append only audit log writer.

This module exposes exactly one verb: ``record``. There is no update and no
delete, here or anywhere else in the application. An audit trail that can be
edited is not an audit trail.

Ordering matters as much as content. Callers must record an action *before*
performing it, so the log answers the question a reviewer actually asks, which
is not "what did you scan" but "what did you attempt to scan, and who asked".
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from app.models.tables import AuditLog


def record(session: Session, *, actor: str, action: str, target: str, detail: Optional[str] = None) -> AuditLog:
    """Append one row and commit it immediately."""
    entry = AuditLog(actor=actor, action=action, target=target, detail=detail)
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry
