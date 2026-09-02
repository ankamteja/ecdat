"""Scan execution.

A bounded thread pool with a per scan state machine. Deliberately not Celery:
a distributed queue is four more moving parts for a workload that is one job
per user action. ``submit`` is the only entry point, so replacing this with a
real broker later means reimplementing one function.

Scan lifecycle::

    queued -> running -> completed
                      -> failed
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import SessionLocal
from app.engine.risk import RiskEngine, dedupe_key
from app.engine import correlate as correlate_engine
from app.models.tables import Asset, Correlation, Finding, Scan
from app.scanners import ScanError, ScanJob, get_scanner

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=settings.max_workers, thread_name_prefix="ecdat-scan")
_engine = RiskEngine()


def submit(scan_id: int) -> None:
    """Queue a scan for background execution."""
    _executor.submit(_run_scan, scan_id)


def _run_scan(scan_id: int) -> None:
    """Execute one scan and persist everything it produced."""
    session: Session = SessionLocal()
    started = dt.datetime.now(dt.timezone.utc)
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return

        scan.status = "running"
        session.commit()

        scanner = get_scanner(scan.kind)
        job = ScanJob(
            scan_id=scan.id,
            target=scan.target,
            authorized=bool(scan.authorized_by),
            fixture=scan.fixture_mode,
        )
        scanner.validate(job)

        raw = correlate_engine.deduplicate(list(scanner.run(job)))
        assets: dict[str, Asset] = {}
        scored_rows: list[dict] = []

        for finding in raw:
            asset = assets.get(finding.locator)
            if asset is None:
                asset = Asset(
                    scan_id=scan.id,
                    kind=finding.asset_kind,
                    locator=finding.locator,
                    meta_json=json.dumps(finding.asset_meta),
                )
                session.add(asset)
                session.flush()
                assets[finding.locator] = asset

            score = _engine.score(finding)
            session.add(
                Finding(
                    scan_id=scan.id,
                    asset_id=asset.id,
                    rule_id=finding.rule_id,
                    algorithm=finding.algorithm,
                    primitive=finding.primitive,
                    key_size=finding.key_size,
                    mode=finding.mode,
                    padding=finding.padding,
                    curve=finding.curve,
                    context=finding.context,
                    exposure=finding.exposure,
                    file_path=finding.file_path,
                    line_no=finding.line_no,
                    evidence_masked=finding.evidence_masked,
                    entropy=finding.entropy,
                    fingerprint=finding.fingerprint,
                    confidence=finding.confidence,
                    classical_score=score.classical,
                    quantum_score=score.quantum,
                    severity=score.severity,
                    pqc_vulnerable=score.pqc_vulnerable,
                    capped_by=score.capped_by,
                    nist_deprecated_after=score.deprecated_after,
                    nist_disallowed_after=score.disallowed_after,
                    standard_refs=score.standard_refs,
                    cwe=score.cwe,
                    dedupe_key=dedupe_key(finding),
                )
            )
            scored_rows.append(
                {
                    "locator": finding.locator,
                    "algorithm": finding.algorithm,
                    "severity": score.severity,
                    "pqc_vulnerable": score.pqc_vulnerable,
                    "asset_kind": finding.asset_kind,
                    "fingerprint": finding.fingerprint,
                }
            )

        # Correlation runs across this scan, and across every prior scan, which
        # is what lets a certificate scanned yesterday link to code scanned now.
        for link in correlate_engine.correlate(scored_rows + _historic_rows(session, scan.id)):
            session.add(
                Correlation(
                    scan_id=scan.id,
                    asset_a=link.asset_a,
                    asset_b=link.asset_b,
                    relation=link.relation,
                    note=link.note,
                )
            )

        scan.status = "completed"
        scan.finished_at = dt.datetime.now(dt.timezone.utc)
        scan.duration_ms = int((scan.finished_at - started).total_seconds() * 1000)
        session.commit()
        logger.info("scan %s completed with %s findings", scan_id, len(raw))

    except ScanError as exc:
        _fail(session, scan_id, started, str(exc))
    except Exception as exc:  # noqa: BLE001 - a scanner crash must not kill the worker
        logger.exception("scan %s crashed", scan_id)
        _fail(session, scan_id, started, f"{type(exc).__name__}: {exc}", traceback.format_exc())
    finally:
        session.close()


def _historic_rows(session: Session, current_scan_id: int) -> list[dict]:
    """Findings from earlier scans, so correlation spans discovery sessions."""
    rows = (
        session.query(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Finding.scan_id != current_scan_id)
        .all()
    )
    return [
        {
            "locator": asset.locator,
            "algorithm": finding.algorithm,
            "severity": finding.severity,
            "pqc_vulnerable": finding.pqc_vulnerable,
            "asset_kind": asset.kind,
            "fingerprint": finding.fingerprint,
        }
        for finding, asset in rows
    ]


def _fail(session: Session, scan_id: int, started: dt.datetime, message: str, detail: str | None = None) -> None:
    """Record a scan as failed and preserve its error.

    Rolls back first, so a partially written scan does not leave half its
    findings behind and appear to have succeeded. The full traceback goes to the
    debug log while the user-facing message stays short.
    """
    session.rollback()
    scan = session.get(Scan, scan_id)
    if scan is None:
        return
    scan.status = "failed"
    scan.error = message
    scan.finished_at = dt.datetime.now(dt.timezone.utc)
    scan.duration_ms = int((scan.finished_at - started).total_seconds() * 1000)
    session.commit()
    if detail:
        logger.debug("scan %s traceback:\n%s", scan_id, detail)
