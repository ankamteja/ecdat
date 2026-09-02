"""End to end: scan, score, correlate, report.

The final test in this module is the product claim, asserted rather than
described: findings from two different scanners joined into one inventory.
"""

from __future__ import annotations

import pytest

from tests.conftest import run_scan


@pytest.fixture(scope="module")
def scans(client, auth_headers, samples_dir):
    """One completed code scan and one completed certificate scan, shared by the suite."""
    return {
        "code": run_scan(client, auth_headers, "code", str(samples_dir / "vulnerable-repo")),
        "certificate": run_scan(client, auth_headers, "certificate", str(samples_dir / "certs")),
    }


def test_scans_complete_and_produce_findings(scans):
    """Baseline: both scan kinds finish and find something, or nothing else below matters."""
    for kind, scan in scans.items():
        assert scan["status"] == "completed", f"{kind}: {scan['error']}"
        assert scan["finding_count"] > 0


def test_a_code_scan_finds_at_least_fifteen_issues(scans):
    """Exceeds the 15-rule claim from the design documents on the bundled sample."""
    assert scans["code"]["finding_count"] >= 15


def test_critical_findings_are_surfaced(client, scans):
    """The severity filter actually returns something on real data, not just on fixtures."""
    response = client.get(
        f"/api/v1/scans/{scans['code']['id']}/findings", params={"severity": "CRITICAL"}
    )
    assert response.json()["count"] >= 1


def test_findings_can_be_filtered(client, scans):
    """An algorithm filter narrows the result set rather than being ignored."""
    scan_id = scans["code"]["id"]
    everything = client.get(f"/api/v1/scans/{scan_id}/findings").json()["count"]
    filtered = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"algorithm": "MD5"}
    ).json()
    assert 0 < filtered["count"] < everything
    assert all(f["algorithm"] == "MD5" for f in filtered["findings"])


def test_every_finding_carries_both_axes_and_a_confidence(client, scans):
    """No finding reaches the API missing a score field, across a real scan's full output."""
    findings = client.get(f"/api/v1/scans/{scans['code']['id']}/findings").json()["findings"]
    for finding in findings:
        assert finding["classical_score"] is not None
        assert finding["quantum_score"] is not None
        assert 0.0 <= finding["confidence"] <= 1.0


def test_pqc_readiness_reports_a_countdown(client, scans):
    """The certificate sample's RSA key produces a real migration row with a real date."""
    report = client.get(f"/api/v1/scans/{scans['certificate']['id']}/pqc").json()
    assert 0 <= report["readiness_percent"] <= 100
    assert report["migrations"], "the sample contains RSA and must produce a migration row"
    row = report["migrations"][0]
    assert row["disallowed_after"] == 2035
    assert row["years_remaining"] >= 0
    assert "remaining" in report["headline"]


def test_the_inventory_unifies_more_than_one_source(client, scans):
    """The product claim.

    Code and certificate findings, discovered by two different scanners, in one
    asset by algorithm matrix. No tool in the comparison can produce this,
    because none of them see both sources.
    """
    inventory = client.get(f"/api/v1/scans/{scans['certificate']['id']}/inventory").json()
    sources = set(inventory["sources"].values())
    assert {"code", "certificate"} <= sources
    assert len(inventory["assets"]) > 1 and len(inventory["algorithms"]) > 1


def test_cross_source_correlation_links_code_to_a_certificate(client, scans):
    """The key pinned in the repository is the key inside the certificate."""
    inventory = client.get(f"/api/v1/scans/{scans['certificate']['id']}/inventory").json()
    shared = [c for c in inventory["correlations"] if c["relation"] == "shared-key-material"]
    assert shared, "no cross source correlation was produced"
    assets = {shared[0]["a"], shared[0]["b"]}
    assert any(a.startswith("cert:") for a in assets)
    assert any(a.endswith(".py") for a in assets)


def test_reports_are_available_in_every_format(client, scans):
    """JSON, CBOM and PDF all succeed for the same scan."""
    scan_id = scans["code"]["id"]
    assert client.get(f"/api/v1/scans/{scan_id}/report.json").status_code == 200
    assert client.get(f"/api/v1/scans/{scan_id}/report.cbom.json").status_code == 200
    response = client.get(f"/api/v1/scans/{scan_id}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] in ("application/pdf", "text/html; charset=utf-8")


def test_a_failed_scan_is_recorded_rather_than_crashing(client, auth_headers):
    """A bad target fails its own scan with a message, and never kills the worker."""
    scan = run_scan(client, auth_headers, "code", "/nonexistent/path/xyz")
    assert scan["status"] == "failed"
    assert "does not exist" in scan["error"]
