"""ECDAT: Enterprise Cryptographic Discovery and Analysis Tool.

Discovers cryptographic usage across source code, TLS endpoints and X.509
certificates, scores every finding on independent classical and quantum axes,
and reports post-quantum migration readiness against the NIST IR 8547 timeline.

Package layout::

    core/       configuration, database, authentication, audit log
    models/     SQLAlchemy tables and Pydantic schemas
    api/v1/     HTTP routers
    scanners/   the three discovery sources behind one interface
    knowledge/  scoring policy as data, not code
    engine/     risk scoring, correlation, PQC readiness
    workers/    background scan execution
    reports/    native JSON, CycloneDX CBOM, PDF
"""
