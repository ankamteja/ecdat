# Contributing

## Setup

```bash
pip install -r requirements.txt
cd backend && uvicorn app.main:app --reload
```

Or `docker compose up --build` for the full stack including the weak TLS demo
target.

## Tests

```bash
pytest
```

71 tests, about three seconds. `pytest.ini` promotes `DeprecationWarning` from
application code to an error, so deprecated APIs cannot silently accumulate.

**The golden cases in `tests/test_risk.py` pin the scoring model.** If one
fails, the model changed. That may be correct, but it should be deliberate, and
the change belongs in `docs/SCORING.md` in the same commit. Do not relax an
assertion to get a green run.

## Adding a detection rule

Rules are data. Add an entry to `backend/app/knowledge/rules.yaml`:

```yaml
  - id: ECDAT-019
    name: Descriptive name
    algorithm: MD5              # must exist in algorithms.yaml
    group: weak-primitive       # weak-primitive | weak-parameter | misuse | secret
    confidence: 0.90
    langs: [py, java, js]
    patterns:
      - '(?i)your_regex_here'
```

Then add a positive and a negative fixture to `samples/vulnerable-repo/` and a
case to `tests/test_scanners.py`. A rule with no negative fixture is a rule
nobody can show is correct.

## Adding an algorithm

Add a row to `backend/app/knowledge/algorithms.yaml`. Every row needs
`base_classical`, `base_quantum`, `quantum_threat` and `refs`.

`quantum_threat` must be one of:

- `shor` for public key algorithms broken outright. These and only these are
  PQC migration candidates.
- `grover` where the security margin halves. Real, but a key size problem, so
  it must not inflate PQC readiness.
- `none`

Getting this wrong is not a cosmetic error: marking a hash as `shor` puts every
finding of it on the migration list and makes the readiness percentage
meaningless.

## Adding a scanner

Implement `app.scanners.base.Scanner` and register it in
`app/scanners/__init__.py`. Two rules:

- `validate()` raises before any work, and for a network scanner before any
  socket opens.
- `run()` yields, never returns a list, so memory stays flat on a large target.

Emit `RawFinding` and nothing else. The risk engine must not be able to tell
which scanner produced a finding.

## Conventions

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

Comments explain **why**, not what. If a decision was non-obvious or a bug was
subtle, the comment records the reasoning so it is not undone later by someone
simplifying it.

## Honesty rules

These are not style preferences. The project's value depends on them.

1. **Never claim a method the code does not use.** Every finding records which
   analysis pass produced it. If a report would say "AST analysis" for a
   pattern match, fix the report.
2. **A coverage gap is a finding, not a silence.** If a check cannot run, say
   so explicitly. A user reading no RC4 finding will conclude the endpoint
   rejects RC4. A false negative that looks like a clean result is the worst
   failure a security scanner has.
3. **Roadmap items stay labelled as roadmap.** The CI/CD webhook returns 501
   rather than pretending. Keep it that way until it works.
