"""Report download endpoints.

Three formats, for three audiences:

* ``report.json``  the full ECDAT record, for a consumer that wants everything.
* ``report.cbom.json``  CycloneDX 1.6, for tooling nobody here wrote.
* ``report.pdf``  for a person who has to sign something.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.api.v1.findings import _require_scan, _rows
from app.core.config import settings
from app.core.db import get_session
from app.models.tables import Correlation, Report
from app.reports import cbom as cbom_writer
from app.reports import native, pdf

router = APIRouter(prefix="/scans", tags=["reports"])


def _payload(session: Session, scan_id: int) -> dict:
    """Assemble the full report body for a scan.

    Shared by the JSON and PDF endpoints so the two cannot drift apart and
    describe the same scan differently.
    """
    scan = _require_scan(session, scan_id)
    findings = _rows(session, scan_id)
    links = [
        {"a": c.asset_a, "b": c.asset_b, "relation": c.relation, "note": c.note}
        for c in session.query(Correlation).filter(Correlation.scan_id == scan_id).all()
    ]
    scan_dict = {
        "id": scan.id,
        "kind": scan.kind,
        "target": scan.target,
        "status": scan.status,
        "started_at": scan.started_at.isoformat(),
        "duration_ms": scan.duration_ms,
        "fixture_mode": scan.fixture_mode,
    }
    return native.build(scan_dict, findings, links)


@router.get("/{scan_id}/report.json")
def report_json(scan_id: int, session: Session = Depends(get_session)) -> JSONResponse:
    """The complete ECDAT record: findings, inventory, correlations, readiness."""
    return JSONResponse(_payload(session, scan_id))


@router.get("/{scan_id}/report.cbom.json")
def report_cbom(
    scan_id: int,
    validate: bool = Query(True, description="Validate against the pinned CycloneDX schema"),
    session: Session = Depends(get_session),
) -> JSONResponse:
    """CycloneDX 1.6 CBOM.

    Validated against the local schema copy by default, so a malformed export
    fails here rather than inside somebody else's pipeline.
    """
    scan = _require_scan(session, scan_id)
    findings = _rows(session, scan_id)
    document = cbom_writer.build(
        {"id": scan.id, "kind": scan.kind, "target": scan.target}, findings
    )
    if validate:
        errors = cbom_writer.validate(document)
        if errors:
            raise HTTPException(
                status_code=500,
                detail={"message": "Generated CBOM failed schema validation.", "errors": errors[:10]},
            )
    return JSONResponse(document)


@router.get("/{scan_id}/report.pdf")
def report_pdf(scan_id: int, session: Session = Depends(get_session)) -> FileResponse:
    """Render the scan as a PDF and record its digest.

    Falls back to HTML with the correct media type when WeasyPrint's rendering
    libraries are unavailable, because a report a reviewer can open in a browser
    beats a stack trace.

    The SHA-256 of whatever was written is stored, so a report handed to a third
    party can later be shown to be unmodified.
    """
    report = _payload(session, scan_id)
    target = settings.report_dir / f"ecdat-scan-{scan_id}.pdf"
    written, media_type = pdf.render(report, target)

    digest = hashlib.sha256(written.read_bytes()).hexdigest()
    session.add(
        Report(scan_id=scan_id, format=written.suffix.lstrip("."), path=str(written), sha256=digest)
    )
    session.commit()
    return FileResponse(written, media_type=media_type, filename=written.name)
