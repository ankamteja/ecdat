#!/bin/sh
# Generate the weak certificate at start up rather than committing key material
# to the repository. A committed private key would be a finding in our own
# codebase, which would be an awkward thing for a cryptography scanner to ship.
set -e

CERT_DIR=/etc/nginx/certs
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/weak.crt" ]; then
    echo "generating deliberately weak certificate (SHA-1, RSA-1024)"
    openssl req -x509 -newkey rsa:1024 -sha1 -nodes \
        -keyout "$CERT_DIR/weak.key" \
        -out "$CERT_DIR/weak.crt" \
        -days 365 \
        -subj "/C=IN/O=ECDAT Demo Target/CN=legacy.ecdat.local" \
        2>/dev/null
    chmod 600 "$CERT_DIR/weak.key"
fi

exec nginx -g 'daemon off;'
