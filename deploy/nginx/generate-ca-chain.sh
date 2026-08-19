#!/usr/bin/env bash
# Generuje pełny łańcuch certyfikatów TLS (Root CA -> Intermediate CA ->
# certyfikat serwera) zamiast pojedynczego certyfikatu samopodpisanego.
#
# Wynik trafia do deploy/nginx/certs/:
#   privkey.pem   - klucz prywatny serwera (używany przez nginx)
#   fullchain.pem - certyfikat serwera + certyfikat pośredni (używany przez nginx)
#   rootCA.pem    - certyfikat głównego CA, DO ZAIMPORTOWANIA w systemie/
#                   przeglądarce klienta, aby uniknąć ostrzeżenia o
#                   niezaufanym certyfikacie (root nie jest częścią
#                   fullchain.pem - klient musi mu zaufać osobno, tak jak
#                   w prawdziwym PKI).
set -euo pipefail

DOMAIN="${1:-localhost}"
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$CERT_DIR"

# --- 1. Root CA ---------------------------------------------------------
openssl genrsa -out "$WORK_DIR/rootCA.key" 4096
openssl req -x509 -new -nodes -key "$WORK_DIR/rootCA.key" -sha256 -days 3650 \
    -subj "/C=PL/O=PyMitiveCA/CN=PyMitiveCA Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$WORK_DIR/rootCA.pem"

# --- 2. Intermediate CA, podpisane przez Root CA ------------------------
openssl genrsa -out "$WORK_DIR/intermediate.key" 4096
openssl req -new -key "$WORK_DIR/intermediate.key" \
    -subj "/C=PL/O=PyMitiveCA/CN=PyMitiveCA Intermediate CA" \
    -out "$WORK_DIR/intermediate.csr"

cat > "$WORK_DIR/intermediate.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF

openssl x509 -req -in "$WORK_DIR/intermediate.csr" \
    -CA "$WORK_DIR/rootCA.pem" -CAkey "$WORK_DIR/rootCA.key" -CAcreateserial \
    -days 1825 -sha256 -extfile "$WORK_DIR/intermediate.ext" \
    -out "$WORK_DIR/intermediate.pem"

# --- 3. Certyfikat serwera, podpisany przez Intermediate CA -------------
openssl genrsa -out "$WORK_DIR/server.key" 2048
openssl req -new -key "$WORK_DIR/server.key" \
    -subj "/C=PL/O=PyMitiveCA/CN=${DOMAIN}" \
    -out "$WORK_DIR/server.csr"

cat > "$WORK_DIR/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in "$WORK_DIR/server.csr" \
    -CA "$WORK_DIR/intermediate.pem" -CAkey "$WORK_DIR/intermediate.key" -CAcreateserial \
    -days 397 -sha256 -extfile "$WORK_DIR/server.ext" \
    -out "$WORK_DIR/server.pem"

# --- 4. Złożenie łańcucha dla nginx (liść + pośredni, bez roota) --------
cat "$WORK_DIR/server.pem" "$WORK_DIR/intermediate.pem" > "$CERT_DIR/fullchain.pem"
cp "$WORK_DIR/server.key" "$CERT_DIR/privkey.pem"
cp "$WORK_DIR/rootCA.pem" "$CERT_DIR/rootCA.pem"

echo "Łańcuch wygenerowany w ${CERT_DIR}:"
echo "  fullchain.pem = certyfikat serwera + intermediate (dla nginx)"
echo "  privkey.pem   = klucz prywatny serwera (dla nginx)"
echo "  rootCA.pem    = zaimportuj do zaufanych CA w systemie/przeglądarce,"
echo "                  żeby połączenie nie było oznaczane jako niezaufane"
