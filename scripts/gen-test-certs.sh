#!/bin/bash
# Generate self-signed certs for localhost testing with wildcard SAN
# These certs allow testing with *.tunn.local.127.0.0.1.nip.io subdomains

set -e

DOMAIN="tunn.local.127.0.0.1.nip.io"
CERT_DIR="./certs"

mkdir -p "$CERT_DIR"

echo "Generating self-signed certificates for $DOMAIN..."

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$CERT_DIR/key.pem" \
  -out "$CERT_DIR/cert.pem" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:*.$DOMAIN,IP:127.0.0.1"

# Also create CA cert (same as server cert for simplicity in dev)
cp "$CERT_DIR/cert.pem" "$CERT_DIR/ca.pem"

echo "Generated certs in $CERT_DIR:"
ls -la "$CERT_DIR"

echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_DIR/cert.pem" -noout -subject -dates -ext subjectAltName
