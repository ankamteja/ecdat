"""Scan submission and status.

The authorisation gate lives here, and the *ordering* inside
:func:`create_scan` is the control itself. The audit record is written before
the scan is queued and before any socket can open. An audit entry written after
the fact records only the scans that finished; one written first records every
scan that was attempted, including the refused ones. Only the second is an
audit trail.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core import audit
from app.core.db import get_session
from app.core.security import current_actor
from app.models.schemas import ScanCreate, ScanOut
from app.models.tables import Finding, Scan
from app.workers import runner

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    payload: ScanCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(current_actor),
) -> ScanOut:
    """Queue a scan.

    A network scan is refused unless the caller explicitly asserts
    authorisation. The refusal is itself recorded, because "who tried to scan
    what" is the question a reviewer actually asks.
    """
    if payload.kind == "tls" and not payload.authorized:
        # Recorded before the refusal is returned, so denied attempts are
        # visible in the audit trail rather than invisible.
        audit.record(
            session,
            actor=actor,
            action="scan.denied",
            target=payload.target,
            detail="Network scan attempted without explicit authorisation.",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "A network scan requires explicit authorisation. "
                "Resubmit with \"authorized\": true to confirm you are permitted "
                "to scan this target."
            ),
        )

    scan = Scan(
        kind=payload.kind,
        target=payload.target,
        status="queued",
        authorized_by=actor if payload.authorized else None,
        fixture_mode=payload.fixture,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # Written before submit(), never after.
    audit.record(
        session,
        actor=actor,
        action="scan.authorized" if payload.authorized else "scan.started",
        target=payload.target,
        detail=f"kind={payload.kind} scan_id={scan.id} fixture={payload.fixture}",
    )

    runner.submit(scan.id)
    return _to_out(scan, 0)


@router.get("", response_model=list[ScanOut])
def list_scans(session: Session = Depends(get_session), limit: int = 50) -> list[ScanOut]:
    """Most recent scans first."""
    scans = session.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
    return [_to_out(s, _count(session, s.id)) for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, session: Session = Depends(get_session)) -> ScanOut:
    """One scan with its current status and finding count.

    Poll this after submitting to watch ``status`` move from ``queued`` through
    ``running`` to ``completed`` or ``failed``.

    Raises:
        HTTPException: 404 if no such scan exists.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"No scan with id {scan_id}.")
    return _to_out(scan, _count(session, scan_id))


def _count(session: Session, scan_id: int) -> int:
    """Number of findings recorded for a scan."""
    return session.query(Finding).filter(Finding.scan_id == scan_id).count()


def _to_out(scan: Scan, findings: int) -> ScanOut:
    """Convert an ORM row to its API representation."""
    return ScanOut(
        id=scan.id,
        kind=scan.kind,
        target=scan.target,
        status=scan.status,
        fixture_mode=scan.fixture_mode,
        authorized_by=scan.authorized_by,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        duration_ms=scan.duration_ms,
        error=scan.error,
        finding_count=findings,
    )
