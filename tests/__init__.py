"""ECDAT test suite.

Organised around the three questions the NCCoE functional test plan for public
key discovery tools poses (NIST SP 1800-38B): does the tool find what is there,
does it avoid reporting what is not, and is the result usable as a managed
asset.

    test_risk.py         golden cases pinning the scoring model
    test_cap_rules.py    cap rules and the confidence floor
    test_scanners.py     scanner passes, secret masking, context classification
    test_certs.py        certificate parsing and lifecycle flags
    test_authz.py        the authorisation gate and the audit trail
    test_cbom.py         CycloneDX export and offline schema validation
    test_integration.py  scan to score to correlate to report

The cases in ``test_risk.py`` are the load-bearing ones. Each encodes a scoring
decision argued for in ``docs/SCORING.md``. A failure there means the model
changed, which may be correct but should be deliberate: fix the model or update
the document, do not relax the assertion.
"""
