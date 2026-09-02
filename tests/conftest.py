"""Shared test fixtures.

Each test module gets an isolated SQLite file, so the suite never depends on
execution order and a failing test cannot poison the next one.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

# Point the application at a throwaway database before anything imports it.
_TMP = tempfile.mkdtemp(prefix="ecdat-tests-")
os.environ["ECDAT_DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ["ECDAT_JWT_SECRET"] = "test-secret-not-a-real-one"


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    """Path to the deliberately vulnerable sample data.

    Session-scoped: the samples are read-only, so every test can share one.
    """
    return REPO_ROOT / "samples"


@pytest.fixture(scope="session")
def client():
    """A TestClient with the application lifespan run, so the admin is seeded."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers(client) -> dict:
    """Bearer token headers for the seeded administrator.

    Session-scoped, so the suite performs one login rather than one per test.
    """
    response = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "ecdat-demo"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def run_scan(client, headers: dict, kind: str, target: str, authorized: bool = True) -> dict:
    """Submit a scan and block until it reaches a terminal state."""
    import time

    response = client.post(
        "/api/v1/scans",
        json={"kind": kind, "target": target, "authorized": authorized},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    for _ in range(100):
        scan = client.get(f"/api/v1/scans/{scan_id}").json()
        if scan["status"] in ("completed", "failed"):
            return scan
        time.sleep(0.1)
    raise AssertionError(f"scan {scan_id} did not finish")
