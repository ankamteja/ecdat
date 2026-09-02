"""Report generation, in three formats for three audiences.

``native``
    The full ECDAT record, for a consumer that wants everything.
``cbom``
    CycloneDX 1.6, for tooling nobody on this project wrote.
``pdf``
    For a person who has to sign something.

All three read the same scored findings, so the formats cannot disagree with
each other about what was found.
"""
