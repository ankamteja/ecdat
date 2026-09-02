"""Health, audit trail and the deliberately unimplemented webhook."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_session
from app.models.tables import AuditLog

router = APIRouter(tags=["system"])


@router.get("/health")
def health() -> dict:
    """Liveness probe, used by the container healthcheck."""
    return {"status": "ok", "app": settings.app_name, "version": settings.version}


@router.get("/audit")
def audit_trail(limit: int = 100, session: Session = Depends(get_session)) -> dict:
    """Read the audit log.

    Read only by design. There is no endpoint to modify or delete these rows,
    here or anywhere else.
    """
    rows = session.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "entries": [
            {
                "id": r.id,
                "ts": r.ts.isoformat(),
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "detail": r.detail,
            }
            for r in rows
        ],
    }


@router.post("/webhooks/scan")
def webhook_stub() -> JSONResponse:
    """CI/CD integration. Not implemented, and says so.

    The route is reserved so the roadmap claim is honest and the path is
    stable, but it returns 501 rather than pretending to work.
    """
    return JSONResponse(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        content={
            "detail": "CI/CD webhook integration is on the roadmap and is not implemented.",
            "roadmap": True,
        },
    )
