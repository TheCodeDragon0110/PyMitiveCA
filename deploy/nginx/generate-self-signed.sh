#!/usr/bin/env bash
# Generuje samopodpisany certyfikat TLS na potrzeby lokalnego / akademickiego
# uruchomienia komponentu bez zarejestrowanej domeny publicznej.
#
# Do prawdziwego wdrożenia produkcyjnego z realną domeną należy zamiast tego
# skorzystać z usługi certbot opisanej w deploy/README.md.
set -euo pipefail

DOMAIN="${1:-localhost}"
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"

mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/C=PL/O=PyMitiveCA/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1"

echo "Wygenerowano samopodpisany certyfikat w ${CERT_DIR}"
