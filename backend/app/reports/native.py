"""Native ECDAT JSON report.

Carries everything the dashboard shows, including both risk axes and the
migration table, so a consumer never has to re-derive a score.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from app.core.config import settings
from app.engine import correlate as correlate_engine
from app.engine import pqc as pqc_engine


def build(scan: dict, findings: list[dict], correlations: list[dict]) -> dict[str, Any]:
    """Assemble the native report.

    Carries the severity breakdown, the inventory, cross-source correlations
    and the full migration table alongside the findings, so a consumer never has
    to re-derive a score or recompute readiness to display it.
    """
    readiness = pqc_engine.assess(findings)
    inventory = correlate_engine.build_inventory(findings)

    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1

    return {
        "tool": {"name": "ECDAT", "version": settings.version},
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scan": scan,
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "assets": len(inventory.assets),
            "algorithms": len(inventory.algorithms),
            "correlations": len(correlations),
        },
        "pqc_readiness": {
            "headline": readiness.headline,
            "readiness_percent": readiness.readiness_percent,
            "total_assets": readiness.total_assets,
            "ready_assets": readiness.ready_assets,
            "at_risk_assets": readiness.at_risk_assets,
            "migrations": [
                {
                    "algorithm": m.algorithm,
                    "assets": m.asset_count,
                    "target": m.target,
                    "standard": m.standard,
                    "deprecated_after": m.deprecated_after,
                    "disallowed_after": m.disallowed_after,
                    "years_remaining": m.years_remaining,
                }
                for m in readiness.migrations
            ],
        },
        "inventory": {
            "assets": inventory.assets,
            "algorithms": inventory.algorithms,
            "sources": inventory.sources,
        },
        "correlations": correlations,
        "findings": findings,
    }
