#!/usr/bin/env bash
# Lab PKI: one classical CA (ECDSA P-256) and one post-quantum CA (ML-DSA-65).
# Needs OpenSSL 3.5 or newer for ML-DSA.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs && cd certs

openssl version | grep -qE 'OpenSSL 3\.([5-9]|[1-9][0-9])' || {
  echo "OpenSSL 3.5+ required for ML-DSA, found: $(openssl version)" >&2; exit 1; }

ca() {  # ca <name> <keyalg args...>
  local name=$1; shift
  openssl genpkey "$@" -out "$name-ca.key" 2>/dev/null
  openssl req -x509 -new -key "$name-ca.key" -days 365 -subj "/CN=pqready lab $name CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -out "$name-ca.pem"
}

leaf() {  # leaf <host> <ca> <keyalg args...>
  local host=$1 ca=$2; shift 2
  openssl genpkey "$@" -out "$host.key" 2>/dev/null
  openssl req -new -key "$host.key" -subj "/CN=$host" -out "$host.csr"
  openssl x509 -req -in "$host.csr" -CA "$ca-ca.pem" -CAkey "$ca-ca.key" -CAcreateserial -days 90 \
    -extfile <(printf "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" "$host") \
    -out "$host.pem" 2>/dev/null
  rm "$host.csr"
}

ca classic -algorithm EC -pkeyopt ec_paramgen_curve:P-256
ca pq -algorithm ML-DSA-65

leaf legacy.lab classic -algorithm RSA -pkeyopt rsa_keygen_bits:2048
leaf classic.lab classic -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf hybrid.lab classic -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf fullpq.lab pq -algorithm ML-DSA-65

cat classic-ca.pem pq-ca.pem > lab-ca-bundle.pem
chmod 644 ./*.key  # lab only: lets the nginx worker read them inside the container
echo "certs written to $(pwd)"
