"""Data definitions.

``tables`` holds the SQLAlchemy ORM models that define what is persisted.
``schemas`` holds the Pydantic models that define what crosses the API
boundary, including ``RawFinding``, the single record type every scanner emits.

The two are kept separate so the storage shape can change without altering the
public API, and so a database column is never accidentally exposed by adding it
to a table.
"""
