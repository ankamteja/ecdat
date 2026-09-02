"""Cross-cutting infrastructure.

Configuration, database session handling, password hashing and token issue,
and the append-only audit writer. Nothing here knows about cryptographic
scanning; it is the plumbing every other package sits on.
"""
