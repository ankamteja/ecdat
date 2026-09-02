"""Version 1 of the HTTP API.

Reads are open and writes require a bearer token. Scan results can be browsed
without signing in, which keeps review friction low, while anything that
changes state or touches the network is authenticated.

Routers are mounted in :mod:`app.main` under the ``/api/v1`` prefix.
"""
