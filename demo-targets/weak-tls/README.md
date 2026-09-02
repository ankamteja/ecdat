# Deliberately weak TLS endpoint

An nginx container configured on purpose with TLS 1.0, TLS 1.1 and weak cipher
suites, serving a certificate signed with SHA-1 over a 1024 bit RSA key.

It exists so the ECDAT network scan can be demonstrated against a real handshake
without pointing a scanner at anything on the internet. Every claim the TLS
scanner makes during a demo is reproducible offline, on a laptop with the
network cable unplugged, and stays inside the tool's own authorisation rules
rather than needing an exception to them.

Do not deploy this. It is a target, not a template.
