"""The authorisation gate and the audit trail.

These assert the security properties the project claims, including the one
that is easiest to get subtly wrong: an audit record has to be written before
the action, not after.
"""

from __future__ import annotations

from tests.conftest import run_scan


def test_network_scan_without_authorisation_is_refused(client, auth_headers):
    """A TLS scan is refused with 403 unless explicitly authorised."""
    response = client.post(
        "/api/v1/scans",
        json={"kind": "tls", "target": "example.com:443", "authorized": False},
        headers=auth_headers,
    )
    assert response.status_code == 403
    assert "authorisation" in response.json()["detail"].lower()


def test_a_refused_scan_still_appears_in_the_audit_trail(client, auth_headers):
    """The point of the ordering.

    A log written after the fact records only scans that ran. One written first
    records what was attempted, which is the question a reviewer actually asks.
    """
    target = "audit-probe.example:8443"
    client.post(
        "/api/v1/scans",
        json={"kind": "tls", "target": target, "authorized": False},
        headers=auth_headers,
    )
    entries = client.get("/api/v1/audit").json()["entries"]
    denied = [e for e in entries if e["action"] == "scan.denied" and e["target"] == target]
    assert denied, "a refused scan left no audit record"
    assert denied[0]["actor"] == "admin"


def test_writes_require_authentication(client):
    """Submitting a scan without a bearer token is refused with 401."""
    response = client.post(
        "/api/v1/scans", json={"kind": "code", "target": "/tmp"}
    )
    assert response.status_code == 401


def test_reads_stay_open_so_results_can_be_reviewed(client):
    """Browsing results needs no login, so review friction stays low."""
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/rules").status_code == 200


def test_bad_credentials_are_rejected_and_recorded(client):
    """A failed login is rejected and appears in the audit trail as auth.failed."""
    response = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == 401
    actions = {e["action"] for e in client.get("/api/v1/audit").json()["entries"]}
    assert "auth.failed" in actions


def test_the_audit_log_is_read_only(client, auth_headers):
    """There must be no route that mutates the audit trail."""
    for method in ("delete", "put", "patch"):
        response = getattr(client, method)("/api/v1/audit", headers=auth_headers)
        assert response.status_code in (404, 405)


def test_the_webhook_stub_is_honest_about_being_unimplemented(client):
    """The CI/CD route returns 501 with a roadmap flag rather than pretending to work."""
    response = client.post("/api/v1/webhooks/scan")
    assert response.status_code == 501
    assert response.json()["roadmap"] is True


def test_an_authorised_scan_records_who_authorised_it(client, auth_headers, samples_dir):
    """The scan row itself, not only the audit log, names who authorised it."""
    scan = run_scan(client, auth_headers, "code", str(samples_dir / "certs"))
    assert scan["authorized_by"] == "admin"
