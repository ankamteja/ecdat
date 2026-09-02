"""Scoring policy, stored as data rather than code.

The YAML files in this directory define which algorithms are weak, how much
each weakness is worth on either axis, which standard says so, and how context
and exposure adjust the result.

Keeping policy out of code means an organisation can tune ECDAT to its own
risk appetite by editing YAML, without forking the scanners. The separation is
borrowed from IBM CBOMkit, which keeps detection, enrichment and policy
evaluation independently replaceable.

Load it through :func:`app.knowledge.loader.load`, which parses and caches.
"""
