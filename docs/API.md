# API reference

Base path `/api/v1`. Interactive documentation is at `/docs` on a running
instance; this page covers the shapes and the behaviour that is not obvious
from the schema.

**Reads are open, writes require a bearer token.** Results can be browsed
without signing in, which makes review easy. Every write, including submitting
a scan, is authenticated.

## Authentication

### `POST /auth/login`

```json
{ "username": "admin", "password": "ecdat-demo" }
```

```json
{ "access_token": "eyJhbGciOi...", "token_type": "bearer" }
```

Send it as `Authorization: Bearer <token>`. Failed attempts are recorded in the
audit log; a log containing only successes is a log of successes, not an audit
trail.

## Scans

### `POST /scans`

Requires authentication. Returns `202 Accepted` and queues the scan.

```json
{
  "kind": "code",
  "target": "../samples/vulnerable-repo",
  "authorized": false,
  "fixture": false
}
```

| Field | Notes |
|---|---|
| `kind` | `code`, `tls` or `certificate` |
| `target` | A path for code and certificates, `host:port` for TLS |
| `authorized` | Required for `tls`. See below |
| `fixture` | Returns canned findings. Labelled in the interface and stored on the scan |

**A TLS scan without `"authorized": true` is refused with 403**, and the
refusal is written to the audit log before the response is returned. The
ordering matters: an audit record written afterwards would contain only scans
that ran.

```json
{
  "detail": "A network scan requires explicit authorisation. Resubmit with \"authorized\": true to confirm you are permitted to scan this target."
}
```

### `GET /scans` and `GET /scans/{id}`

Status is `queued`, `running`, `completed` or `failed`. A failed scan records
its error rather than disappearing.

## Findings

### `GET /scans/{id}/findings`

| Query parameter | Effect |
|---|---|
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `algorithm` | Exact match, case insensitive |
| `source` | `code`, `tls`, `certificate` |
| `min_confidence` | Float, default 0.0 |

Sorted by severity, then by the higher of the two scores.

```json
{
  "scan_id": 1,
  "count": 28,
  "findings": [
    {
      "algorithm": "RSA",
      "locator": "auth_service.py",
      "file_path": "auth_service.py",
      "line_no": 33,
      "key_size": 1024,
      "context": "security",
      "exposure": "internal",
      "classical_score": 10.0,
      "quantum_score": 9.5,
      "severity": "CRITICAL",
      "confidence": 0.95,
      "pqc_vulnerable": true,
      "nist_deprecated_after": 2030,
      "nist_disallowed_after": 2035,
      "standard_refs": "SHOR1994, IR8547",
      "cwe": "CWE-326",
      "evidence_masked": "key_size=1024"
    }
  ]
}
```

`evidence_masked` never contains a secret literal. For a detected key it holds
the first four characters and a length; the value itself is represented only by
`fingerprint`, a truncated SHA-256 digest.

### `GET /scans/{id}/inventory`

The unified matrix, built across **every** scan rather than only this one,
because the claim is that code, TLS and certificate results end up in one
table.

```json
{
  "assets": ["auth_service.py", "cert:api.ecdat.sample"],
  "algorithms": ["MD5", "RSA"],
  "sources": { "auth_service.py": "code", "cert:api.ecdat.sample": "certificate" },
  "cells": {
    "auth_service.py": { "MD5": { "count": 2, "severity": "CRITICAL", "pqc_vulnerable": false } }
  },
  "correlations": [
    {
      "a": "cert:api.ecdat.sample",
      "b": "config/tls_pinning.py",
      "relation": "shared-key-material",
      "note": "Identical public key fingerprint 6f6ffe0f8d59055c."
    }
  ]
}
```

Correlations are the product claim. Two joins exist: identical public key
fingerprint across sources, and a TLS hostname matching a certificate subject.

### `GET /scans/{id}/pqc`

```json
{
  "headline": "RSA found in 4 assets. Deprecated by NIST after 2030, disallowed after 2035. 9 years remaining.",
  "readiness_percent": 37.5,
  "ready_assets": 3,
  "at_risk_assets": 5,
  "total_assets": 8,
  "migrations": [
    {
      "algorithm": "RSA",
      "assets": 4,
      "target": "ML-KEM-768",
      "standard": "FIPS 203",
      "deprecated_after": 2030,
      "disallowed_after": 2035,
      "years_remaining": 9
    }
  ]
}
```

Readiness counts Shor-vulnerable algorithms only. Grover-affected primitives
such as AES-128 are a key size problem, not a migration problem, and counting
them would make the percentage meaningless.

## Reports

| Endpoint | Format |
|---|---|
| `GET /scans/{id}/report.json` | Native ECDAT record |
| `GET /scans/{id}/report.cbom.json` | CycloneDX 1.6 CBOM |
| `GET /scans/{id}/report.pdf` | PDF, falls back to HTML if the renderer is unavailable |

The CBOM validates against the pinned local schema by default, so a malformed
export fails here rather than inside a consumer's pipeline. Pass
`?validate=false` to skip.

Findings map onto all four `assetType` values: `algorithm` for code,
`certificate`, `protocol` for TLS, and `related-crypto-material` for detected
key material regardless of which scanner found it. ECDAT scoring travels as
namespaced `ecdat:` properties, because CycloneDX has no dual-axis score field
and overloading one that means something else would be worse than adding a
property.

## Knowledge base

### `GET /rules`

The detection catalogue and the algorithm table, self-documenting. Every rule
names the standard behind it, which makes this a live and verifiable version of
the reference list rather than a static claim.

## System

| Endpoint | Behaviour |
|---|---|
| `GET /health` | Liveness |
| `GET /audit` | The audit trail, read only. No route exists to modify it |
| `POST /webhooks/scan` | Returns **501**. CI/CD integration is roadmap and says so rather than pretending to work |
