"""CycloneDX CBOM export and offline schema validation."""

from __future__ import annotations

import pytest

from app.reports import cbom
from tests.conftest import run_scan


@pytest.fixture(scope="module")
def scans(client, auth_headers, samples_dir):
    """One completed code scan and one completed certificate scan.

    Module-scoped: the CBOM tests only read these, so one pair of scans serves
    the whole file.
    """
    return {
        "code": run_scan(client, auth_headers, "code", str(samples_dir / "vulnerable-repo")),
        "certificate": run_scan(client, auth_headers, "certificate", str(samples_dir / "certs")),
    }


def test_the_document_declares_cyclonedx_1_6(client, scans):
    """The spec version is the exact string a validator expects, not a float."""
    document = client.get(f"/api/v1/scans/{scans['code']['id']}/report.cbom.json").json()
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"


def test_generated_documents_validate_against_the_pinned_schema(client, scans):
    """Validation is on by default, so a 200 means the document is valid."""
    for scan in scans.values():
        response = client.get(f"/api/v1/scans/{scan['id']}/report.cbom.json")
        assert response.status_code == 200, response.text


def test_validation_uses_a_local_schema_copy():
    """Validation must work with no network, which is the sovereignty claim."""
    from app.core.config import settings

    assert (settings.schema_dir / cbom.SCHEMA_FILE).exists()


def test_components_are_typed_as_cryptographic_assets(client, scans):
    """Every component uses the CycloneDX cryptographic-asset type, not a generic one."""
    document = client.get(f"/api/v1/scans/{scans['code']['id']}/report.cbom.json").json()
    assert document["components"]
    assert all(c["type"] == "cryptographic-asset" for c in document["components"])


def test_asset_types_span_the_sources_scanned(client, scans):
    """Code and certificate scans between them cover three of the four assetType values."""
    seen = set()
    for scan in scans.values():
        document = client.get(f"/api/v1/scans/{scan['id']}/report.cbom.json").json()
        seen |= {c["cryptoProperties"]["assetType"] for c in document["components"]}
    assert {"algorithm", "certificate", "related-crypto-material"} <= seen


def test_the_protocol_asset_type_is_produced_for_tls():
    """Covered directly, since a live TLS target is not available in the suite."""
    document = cbom.build(
        {"id": 1, "kind": "tls", "target": "host:443"},
        [
            {
                "asset_kind": "tls",
                "algorithm": "TLSv1.0",
                "locator": "host:443",
                "primitive": "protocol",
                "severity": "CRITICAL",
                "classical_score": 9.2,
                "quantum_score": 4.0,
                "confidence": 0.95,
                "pqc_vulnerable": False,
            }
        ],
    )
    assert cbom.validate(document) == []
    properties = document["components"][0]["cryptoProperties"]
    assert properties["assetType"] == "protocol"
    assert properties["protocolProperties"]["version"] == "1.0"


def test_scoring_travels_as_namespaced_properties(client, scans):
    """CycloneDX has no dual axis score field, so it must not be forced into one."""
    document = client.get(f"/api/v1/scans/{scans['code']['id']}/report.cbom.json").json()
    names = {p["name"] for p in document["components"][0]["properties"]}
    assert {"ecdat:classicalScore", "ecdat:quantumScore", "ecdat:severity"} <= names


def test_secret_material_is_exported_by_fingerprint_only(client, scans, samples_dir):
    """The key material claim must hold in every export format, not only the API."""
    planted = "Zk4Qm8Xr2TyUz1Vn7Wk3Pl6Ab5Cd0Eg9Hj7Ns"
    response = client.get(f"/api/v1/scans/{scans['code']['id']}/report.cbom.json")
    assert planted not in response.text
