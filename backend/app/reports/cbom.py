"""CycloneDX 1.6 Cryptography Bill of Materials export.

CycloneDX 1.6 is the first specification version with native cryptographic
asset support. The ``cryptoProperties`` object and its ``assetType`` enum of
``algorithm``, ``certificate``, ``protocol`` and ``related-crypto-material``
are read from the local schema copy in ``schemas/``, and generated documents
are validated against that file rather than against a fetched one, so the
export works on an air gapped host.

Emitting a published format rather than a bespoke JSON shape is what makes
ECDAT output ingestible by tooling nobody on this project wrote.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from app.core.config import settings

SPEC_VERSION = "1.6"
SCHEMA_FILE = "cyclonedx-1.6.schema.json"

#: Which ECDAT finding maps onto which CycloneDX asset type.
_ASSET_TYPE_BY_SOURCE = {
    "code": "algorithm",
    "certificate": "certificate",
    "tls": "protocol",
}

#: Cryptographic primitive names accepted by the specification.
_PRIMITIVE_MAP = {
    "hash": "hash",
    "block-cipher": "block-cipher",
    "stream-cipher": "stream-cipher",
    "public-key": "signature",
    "key-exchange": "key-agree",
    "kem": "kem",
    "signature": "signature",
    "aead": "ae",
    "kdf": "kdf",
    "rng": "drbg",
}


@lru_cache(maxsize=1)
def _schema() -> dict:
    """Load and cache the pinned CycloneDX schema.

    Read from disk rather than fetched, so validation works on an air-gapped
    host and cannot silently change when the published spec is updated.
    """
    with open(settings.schema_dir / SCHEMA_FILE, encoding="utf-8") as handle:
        return json.load(handle)


def build(scan: dict, findings: list[dict]) -> dict:
    """Produce a CycloneDX 1.6 CBOM document for one scan."""
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

    components: list[dict] = []
    seen: set[str] = set()
    for finding in findings:
        component = _component(finding)
        if component is None:
            continue
        key = component["bom-ref"]
        if key in seen:
            continue
        seen.add(key)
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "ECDAT",
                        "version": settings.version,
                        "description": "Enterprise Cryptographic Discovery and Analysis Tool",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"scan-{scan['id']}",
                "name": scan["target"],
                "description": f"ECDAT {scan['kind']} scan {scan['id']}",
            },
        },
        "components": components,
    }


def _component(finding: dict) -> Optional[dict]:
    """Map one scored finding to a CycloneDX crypto-asset component."""
    source = finding.get("asset_kind", "code")
    asset_type = _ASSET_TYPE_BY_SOURCE.get(source, "algorithm")

    # Detected key material is its own asset type, whatever source found it.
    if finding.get("algorithm") == "HARDCODED-SECRET":
        asset_type = "related-crypto-material"

    name = finding.get("algorithm") or "unknown"
    locator = finding.get("locator", "unknown")
    ref = f"crypto/{asset_type}/{name}/{locator}"

    crypto: dict[str, Any] = {"assetType": asset_type}

    if asset_type == "algorithm":
        properties: dict[str, Any] = {}
        primitive = _PRIMITIVE_MAP.get(finding.get("primitive") or "")
        if primitive:
            properties["primitive"] = primitive
        if finding.get("key_size"):
            properties["parameterSetIdentifier"] = str(finding["key_size"])
        if finding.get("curve"):
            properties["curve"] = finding["curve"]
        properties["executionEnvironment"] = "software-plain-ram"
        properties["implementationPlatform"] = "generic"
        crypto["algorithmProperties"] = properties

    elif asset_type == "certificate":
        crypto["certificateProperties"] = {
            "subjectName": locator.removeprefix("cert:"),
            "signatureAlgorithmRef": name,
        }

    elif asset_type == "protocol":
        version = name.replace("TLSv", "") if name.startswith("TLSv") else None
        crypto["protocolProperties"] = {"type": "tls", **({"version": version} if version else {})}

    else:  # related-crypto-material
        crypto["relatedCryptoMaterialProperties"] = {
            "type": "private-key",
            "state": "active",
            # The literal is never present. Only the fingerprint travels.
            **({"id": finding["fingerprint"]} if finding.get("fingerprint") else {}),
        }

    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "description": finding.get("evidence_masked") or "",
        "cryptoProperties": crypto,
        "properties": _properties(finding),
    }


def _properties(finding: dict) -> list[dict]:
    """ECDAT specific scoring, carried as namespaced name value pairs.

    CycloneDX has no field for a dual axis risk score, so it goes here rather
    than being forced into a field that means something else.
    """
    out = [
        {"name": "ecdat:severity", "value": str(finding.get("severity"))},
        {"name": "ecdat:classicalScore", "value": str(finding.get("classical_score"))},
        {"name": "ecdat:quantumScore", "value": str(finding.get("quantum_score"))},
        {"name": "ecdat:confidence", "value": str(finding.get("confidence"))},
        {"name": "ecdat:pqcVulnerable", "value": str(bool(finding.get("pqc_vulnerable"))).lower()},
    ]
    for key, prop in (
        ("cwe", "ecdat:cwe"),
        ("standard_refs", "ecdat:references"),
        ("rule_id", "ecdat:ruleId"),
        ("nist_disallowed_after", "ecdat:nistDisallowedAfter"),
    ):
        if finding.get(key):
            out.append({"name": prop, "value": str(finding[key])})
    return out


def validate(document: dict) -> list[str]:
    """Validate against the pinned local schema. Returns a list of errors."""
    try:
        import jsonschema
    except ImportError:  # pragma: no cover
        return ["jsonschema is not installed, validation skipped"]

    validator = jsonschema.Draft7Validator(_schema())
    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in validator.iter_errors(document)]


def write(document: dict, path: Path) -> Path:
    """Write a CBOM to disk, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path
