"""Analysis over findings.

Three stages, deliberately separate:

``risk``
    Scores one finding on two independent axes.
``correlate``
    Deduplicates, builds the asset-by-algorithm matrix, and links assets that
    different scanners discovered independently.
``pqc``
    Turns scored findings into a migration plan with a deadline.

None of these modules know how a finding was discovered. They operate on
:class:`app.models.schemas.RawFinding` and plain dictionaries, which is what
allows a new scanner to be added without touching any of them.
"""
