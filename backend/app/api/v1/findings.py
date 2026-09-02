"""Finding queries, inventory matrix, PQC readiness and the rule catalogue."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.db import get_session
from app.engine import correlate as correlate_engine
from app.engine import pqc as pqc_engine
from app.knowledge.loader import load
from app.models.tables import Asset, Correlation, Finding, Scan

router = APIRouter(tags=["findings"])


def _rows(session: Session, scan_id: Optional[int] = None) -> list[dict]:
    """Join findings to assets and flatten into plain dictionaries."""
    query = session.query(Finding, Asset).join(Asset, Finding.asset_id == Asset.id)
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "locator": a.locator,
            "asset_kind": a.kind,
            "rule_id": f.rule_id,
            "algorithm": f.algorithm,
            "primitive": f.primitive,
            "key_size": f.key_size,
            "context": f.context,
            "exposure": f.exposure,
            "file_path": f.file_path,
            "line_no": f.line_no,
            "evidence_masked": f.evidence_masked,
            "confidence": f.confidence,
            "classical_score": f.classical_score,
            "quantum_score": f.quantum_score,
            "severity": f.severity,
            "pqc_vulnerable": f.pqc_vulnerable,
            "capped_by": f.capped_by,
            "nist_deprecated_after": f.nist_deprecated_after,
            "nist_disallowed_after": f.nist_disallowed_after,
            "standard_refs": f.standard_refs,
            "cwe": f.cwe,
            "fingerprint": f.fingerprint,
        }
        for f, a in query.all()
    ]


def _require_scan(session: Session, scan_id: int) -> Scan:
    """Fetch a scan or raise 404.

    Raises:
        HTTPException: 404 if no such scan exists.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"No scan with id {scan_id}.")
    return scan


@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: int,
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM or LOW"),
    algorithm: Optional[str] = None,
    source: Optional[str] = Query(None, description="code, tls or certificate"),
    min_confidence: float = 0.0,
    session: Session = Depends(get_session),
) -> dict:
    """Findings for one scan, filtered and ranked.

    Sorted by severity, then by the higher of the two axis scores, so the most
    urgent finding is always first regardless of which axis made it urgent.

    Args:
        severity: CRITICAL, HIGH, MEDIUM or LOW.
        algorithm: Exact match, case insensitive.
        source: Restrict to one discovery source.
        min_confidence: Drop findings the scanner was less sure about.
    """
    _require_scan(session, scan_id)
    rows = _rows(session, scan_id)
    if severity:
        rows = [r for r in rows if r["severity"] == severity.upper()]
    if algorithm:
        rows = [r for r in rows if r["algorithm"].lower() == algorithm.lower()]
    if source:
        rows = [r for r in rows if r["asset_kind"] == source]
    rows = [r for r in rows if r["confidence"] >= min_confidence]

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: (order[r["severity"]], -max(r["classical_score"], r["quantum_score"])))
    return {"scan_id": scan_id, "count": len(rows), "findings": rows}


@router.get("/scans/{scan_id}/inventory")
def scan_inventory(scan_id: int, session: Session = Depends(get_session)) -> dict:
    """The unified asset by algorithm matrix.

    Built across every scan rather than only this one, because the whole claim
    is that code, TLS and certificate results end up in one table.
    """
    _require_scan(session, scan_id)
    rows = _rows(session)
    inventory = correlate_engine.build_inventory(rows)
    links = session.query(Correlation).all()
    return {
        "assets": inventory.assets,
        "algorithms": inventory.algorithms,
        "sources": inventory.sources,
        "cells": {
            asset: {
                algorithm: {
                    "count": cell.count,
                    "severity": cell.worst_severity,
                    "pqc_vulnerable": cell.pqc_vulnerable,
                }
                for algorithm, cell in by_algorithm.items()
            }
            for asset, by_algorithm in inventory.cells.items()
        },
        "correlations": [
            {"a": c.asset_a, "b": c.asset_b, "relation": c.relation, "note": c.note} for c in links
        ],
    }


@router.get("/scans/{scan_id}/pqc")
def scan_pqc(scan_id: int, session: Session = Depends(get_session)) -> dict:
    """Post quantum readiness across everything discovered so far."""
    _require_scan(session, scan_id)
    report = pqc_engine.assess(_rows(session))
    return {
        "headline": report.headline,
        "readiness_percent": report.readiness_percent,
        "total_assets": report.total_assets,
        "ready_assets": report.ready_assets,
        "at_risk_assets": report.at_risk_assets,
        "migrations": [
            {
                "algorithm": m.algorithm,
                "assets": m.asset_count,
                "findings": m.finding_count,
                "target": m.target,
                "standard": m.standard,
                "deprecated_after": m.deprecated_after,
                "disallowed_after": m.disallowed_after,
                "years_remaining": m.years_remaining,
            }
            for m in report.migrations
        ],
    }


@router.get("/rules")
def list_rules() -> dict:
    """The detection knowledge base, self documenting.

    This endpoint is a live and verifiable version of the reference list in the
    project documentation: every rule states the standard behind it.
    """
    kb = load()
    return {
        "count": len(kb.rules),
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "algorithm": r.algorithm,
                "group": r.group,
                "confidence": r.confidence,
                "languages": list(r.langs),
                "patterns": len(r.compiled),
                "references": kb.algorithm(r.algorithm).reference_titles,
                "cwe": kb.algorithm(r.algorithm).cwe,
            }
            for r in kb.rules
        ],
        "algorithms": {
            name: {
                "classical": e.base_classical,
                "quantum": e.base_quantum,
                "quantum_threat": e.quantum_threat,
                "status": e.status,
                "cwe": e.cwe,
                "references": e.reference_titles,
                "deprecated_after": e.deprecated_after,
                "disallowed_after": e.disallowed_after,
            }
            for name, e in sorted(kb.algorithms.items())
        },
    }
