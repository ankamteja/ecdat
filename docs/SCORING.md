# The scoring model

ECDAT scores every finding on two independent axes and never averages them.
This document explains where the numbers come from, why the structure is shaped
the way it is, and what it produces on real input.

## Why a new model exists at all

There is no CVSS equivalent for cryptographic weakness. MITRE's CWSS
documentation states the consequence directly: automated tools each perform
their own custom scoring, and as a result multiple tools produce inconsistent
scores for the same weakness.

So ECDAT needed a model. The important design decision is that it is
**assembled from published work rather than invented**, because the question a
reviewer will ask is not "what is your formula" but "why should I believe this
number".

| Borrowed | From | What it contributes |
|---|---|---|
| Structure | MITRE CWSS | Separate metric groups (base finding including confidence, attack surface, environmental) rather than one flat number |
| Mechanics | Qualys SSL Labs rating guide | Weighted inputs, numeric-to-band mapping, and cap rules where one disqualifying defect overrides an otherwise acceptable score |
| Quantum timeline | NIST IR 8547 ipd, November 2024 | Published deprecation dates instead of an invented urgency value |
| Algorithm status | NIST SP 800-131A Rev 2, FIPS 180-4 / 197 / 203 / 204 / 205 | Which algorithms are approved, deprecated or disallowed |
| Taxonomy | CWE-310, CWE-326, CWE-327 | A CWE id on every finding, so output drops into standard vulnerability pipelines |

![Scoring provenance](images/10-scoring-provenance.png)

## The formula

```
classical = clamp(base_classical + param_penalty, 0, 10) * w_context * w_exposure
quantum   = base_quantum                                 * w_context * w_exposure

severity  = band(max(classical, quantum))     subject to the cap rules below
```

![Risk engine](images/07-risk-engine.png)

### The two axes are never averaged

This is the single most important property of the model.

RSA-2048 scores **3.0 classical** and **9.5 quantum**. It is correctly
implemented, currently approved, and disallowed by NIST after 2035. An average
of 6.25 bands as MEDIUM and the finding vanishes into the noise, which is
precisely the failure this tool was built to correct.

There is a test that asserts this, and it first proves the alternative
implementation would produce a different result:

```python
def test_the_two_axes_are_never_averaged(engine):
    score = engine.score(finding(algorithm="RSA", key_size=2048))
    average = (score.classical + score.quantum) / 2
    assert 4.0 <= average < 7.0, "guard: the average really would band lower"
    assert score.severity == "CRITICAL", "severity must follow the maximum, not the mean"
```

### Shor and Grover are not the same problem

A subtle modelling error worth naming, because the obvious implementation gets
it wrong.

- **Grover** halves the effective security margin of symmetric primitives and
  hashes. AES-128 and SHA-256 are affected. The fix is a larger key.
- **Shor** breaks public key cryptography outright. RSA, ECDSA, ECDH, DH and
  DSA are affected. The only fix is migration to ML-KEM or ML-DSA.

Treating both as "quantum vulnerable" would put every MD5 finding on the PQC
migration list and make the readiness percentage meaningless. Each algorithm
carries an explicit `quantum_threat` of `shor`, `grover` or `none`, and PQC
readiness counts `shor` only. MD5 stays CRITICAL on the classical axis, which
is where it belongs.

## Base values

One row per algorithm in `backend/app/knowledge/algorithms.yaml`. Every row
carries the document it comes from and a CWE id, so every score on the
dashboard traces to a published standard rather than to a developer's opinion.

| Class | Examples | Classical | Quantum | Reference |
|---|---|---|---|---|
| Broken | MD5, SHA-1, DES, RC4, ECB | 10.0 | 4.0 | Wang 2004, SHAttered 2017, RFC 7465 |
| Deprecated | 3DES, TLS 1.0 and 1.1, SSLv3 | 8.0 | 4.0 | SWEET32, RFC 8996, SP 800-131A |
| Weak usage | PKCS1 v1.5, static IV, weak KDF | 6.0 to 7.0 | 0.0 | SP 800-131A |
| Approved, Shor-vulnerable at 112 bit | RSA-2048, ECDSA P-256, ECDH, DH | 2.0 to 3.0 | 9.5 | IR 8547: deprecated 2030, disallowed 2035 |
| Approved, Grover-weakened | AES-128, SHA-256 | 1.0 | 4.0 | Grover 1996 |
| Strong | AES-256, ChaCha20-Poly1305, SHA-384, TLS 1.3 | 0.0 | 1.0 | FIPS 197, FIPS 180-4 |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA | 0.0 | 0.0 | FIPS 203, 204, 205 |
| Hardcoded key material | any | 9.0 | 0.0 | OWASP A02 |

## Weights

The CWSS environmental and attack surface groups, made concrete. These are what
separate a real finding from a lint warning.

| Weight | Condition | Value |
|---|---|---|
| `w_context` | Key exchange, signature, authentication, encryption at rest, password hashing | 1.0 |
| | Integrity checksum or clearly non-security use | 0.4 |
| | Test, fixture or vendor directory | 0.3 |
| `w_exposure` | Internet-reachable endpoint | 1.15 |
| | Internal endpoint or repository source | 1.0 |
| | Sample or documentation | 0.5 |

Context is judged on the path **inside the scan target**, never the absolute
path. Scanning a repository that happens to live under a directory called
`samples` or `test` must not downweight every finding in it.

Bands: **CRITICAL** at 9.0 and above, **HIGH** 7.0 to 8.9, **MEDIUM** 4.0 to
6.9, **LOW** below 4.0.

## Cap rules

Adapted from the SSL Labs pattern where one disqualifying defect caps the grade
regardless of the rest of the configuration. Some cryptographic defects work
the same way, and a weighted average must not be able to argue them down.

- A broken-class algorithm in a security context caps at **CRITICAL**.
- A hardcoded key or private key literal caps at **CRITICAL**, in any context.
- Disabled certificate verification caps at **CRITICAL**.
- An asset with nothing on either axis cannot be inflated above **LOW**.

## Confidence

Per finding, 0.70 to 0.95, corresponding to the CWSS base finding group.

| Source | Confidence |
|---|---|
| AST match, TLS handshake, certificate field | 0.95 |
| Pattern rule with a distinctive signature | 0.85 to 0.90 |
| Shannon entropy alone | 0.70 |
| Coverage gap, where the check could not run | 0.60 |

A finding below 0.70 is **demoted rather than escalated** and can never reach
CRITICAL. This is the concrete form of "requires manual review" and it is the
honest answer to cryptography the tool cannot resolve.

The 0.60 tier is deliberately below the floor. It reports the absence of
information, not the presence of a weakness, and is used when a check could not
be performed at all, for example probing for RC4 on an OpenSSL build that has
removed it. Reporting nothing in that case would let a user read silence as
safety.

## Worked example

The same `hashlib.md5` call, in two places in the same repository:

| | Signing an auth token | Cache key under `tests/` |
|---|---|---|
| Base classical | 10.0 | 10.0 |
| `w_context` | 1.0 (security) | 0.3 (test) |
| Classical | **10.0** | **3.0** |
| Quantum | 4.0 | 1.2 |
| Cap rule | broken-algorithm | none |
| **Severity** | **CRITICAL** | **LOW** |

A tool that scores those identically produces a report nobody reads.

## Post-quantum readiness

Readiness is the percentage of assets carrying no Shor-vulnerable findings,
paired with a migration table:

| From | To | Standard |
|---|---|---|
| RSA, ECDH, DH key establishment | ML-KEM-768 | FIPS 203 |
| RSA, ECDSA, EdDSA, DSA signatures | ML-DSA-65 | FIPS 204 |
| Long-lived firmware and code signing | SLH-DSA | FIPS 205 |
| AES-128 | AES-256 | FIPS 197, Grover margin |

![Migration timeline](images/11-migration-timeline.png)

Because the dates are published, the dashboard reports a deadline rather than
an adjective:

> RSA found in 4 assets. Deprecated by NIST after 2030, disallowed after 2035.
> **9 years remaining.**

"Quantum vulnerable" tells an organisation nothing it did not know. A named
algorithm, an asset count and a date is a migration plan.
