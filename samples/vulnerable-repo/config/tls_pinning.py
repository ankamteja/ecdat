"""Pinned public key for the upstream API.

This is the *same* key as samples/certs/modern-rsa2048.pem. It is planted
here deliberately so ECDAT can demonstrate the cross source correlation:
the key pinned in this repository and the key inside that certificate are
one key, and no single purpose scanner can tell you that.
"""

UPSTREAM_API_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyntCdXX0yYLHrDm9B8c+
IwwkHw55uSC744Qz6MSWk6kikNnR22vC4zUAvKT7SG2iQwg4k2847bDwjD5Ippmh
pUjCBgy+wHGvzzggrlP2TFtNs8wGrffB4P80egfdbk6Pv5LLO8l9bmxcTfFpm7Gi
8drCneIC9fMOepXOv7pNgpDANxPdPDrGHhKuC0y0v7X8NW2HNkEKoZTmHEPethkr
u2qNcKCrMHmJRIReppNQKTwiS81s+tY2h0orAUPr/TiUqq8dve5E9krws7B0H0jz
L2fmgmUcI3Zpc5YREQexroh3/S6RT5mALR64vENjdBtRFA4rQB+EFIvVKPYbLlqe
pwIDAQAB
-----END PUBLIC KEY-----
"""
