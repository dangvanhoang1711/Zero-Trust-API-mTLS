#!/bin/bash
set -euo pipefail

# === Zero-Trust PKI Hierarchy ===
#
#   Root CA  (self-signed, offline)
#     └── signs ──► RA Intermediate CA
#                     ├── signs ──► Server cert (Envoy, CN=localhost)
#                     └── signs ──► Client cert (CN=demo-client)
#
# Root CA is kept offline (never used to sign leaf certs directly).
# RA Intermediate CA is the daily operational CA.
# Leaf certs are signed by RA only.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"  # = project_root/ (parent of infra/)

PKI_DIR="$SCRIPT_DIR/pki"
CERTS_DIR="$SCRIPT_DIR/certs"
ENVOY_TLS_DIR="$PROJECT_ROOT/envoy_config/tls"
ENVOY_TRUST_DIR="$ENVOY_TLS_DIR/trust"

mkdir -p "$PKI_DIR" "$CERTS_DIR" "$ENVOY_TLS_DIR" "$ENVOY_TRUST_DIR"

DAYS_ROOT=3650
DAYS_RA=1825
DAYS_LEAF=730

echo "=== 1. Root CA (self-signed, offline) ==="
openssl genrsa -out "$PKI_DIR/root-ca.key" 4096
openssl req -x509 -new -nodes -key "$PKI_DIR/root-ca.key" \
  -sha256 -days $DAYS_ROOT \
  -subj "/CN=Zero Trust Root CA" \
  -out "$PKI_DIR/root-ca.crt"
echo "  Root CA: $PKI_DIR/root-ca.crt"

echo ""
echo "=== 2. RA Intermediate CA (signed by Root CA) ==="
openssl genrsa -out "$PKI_DIR/ra-intermediate.key" 4096
openssl req -new -key "$PKI_DIR/ra-intermediate.key" \
  -subj "/CN=Zero Trust RA Intermediate CA" \
  -out "$PKI_DIR/ra-intermediate.csr"

cat > "$PKI_DIR/ra-ext.cnf" <<RAEXT
[v3_ca]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
RAEXT

openssl x509 -req -in "$PKI_DIR/ra-intermediate.csr" \
  -CA "$PKI_DIR/root-ca.crt" -CAkey "$PKI_DIR/root-ca.key" \
  -CAcreateserial -out "$PKI_DIR/ra-intermediate.crt" \
  -days $DAYS_RA -sha256 -extfile "$PKI_DIR/ra-ext.cnf" -extensions v3_ca

echo "  RA Intermediate CA: $PKI_DIR/ra-intermediate.crt"

echo ""
echo "=== 3. Server cert (Envoy, CN=localhost, signed by RA) ==="
openssl genrsa -out "$PKI_DIR/server.key" 2048

cat > "$PKI_DIR/server.cnf" <<SRVCNF
[req]
distinguished_name = dn
req_extensions = ext
prompt = no

[dn]
CN = localhost

[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,DNS:envoy-service.default.svc.cluster.local,IP:127.0.0.1
SRVCNF

openssl req -new -key "$PKI_DIR/server.key" \
  -config "$PKI_DIR/server.cnf" \
  -out "$PKI_DIR/server.csr"

openssl x509 -req -in "$PKI_DIR/server.csr" \
  -CA "$PKI_DIR/ra-intermediate.crt" -CAkey "$PKI_DIR/ra-intermediate.key" \
  -CAcreateserial -out "$PKI_DIR/server.crt" \
  -days $DAYS_LEAF -sha256 -extfile "$PKI_DIR/server.cnf" -extensions ext

echo "  Server cert: $PKI_DIR/server.crt"

echo ""
echo "=== 4. Client cert (CN=demo-client, signed by RA) ==="
openssl genrsa -out "$PKI_DIR/client.key" 2048

cat > "$PKI_DIR/client.cnf" <<CLTCNF
[req]
distinguished_name = dn
req_extensions = ext
prompt = no

[dn]
CN = demo-client

[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
CLTCNF

openssl req -new -key "$PKI_DIR/client.key" \
  -config "$PKI_DIR/client.cnf" \
  -out "$PKI_DIR/client.csr"

openssl x509 -req -in "$PKI_DIR/client.csr" \
  -CA "$PKI_DIR/ra-intermediate.crt" -CAkey "$PKI_DIR/ra-intermediate.key" \
  -CAcreateserial -out "$PKI_DIR/client.crt" \
  -days $DAYS_LEAF -sha256 -extfile "$PKI_DIR/client.cnf" -extensions ext

echo "  Client cert: $PKI_DIR/client.crt"

echo ""
echo "=== 5. Build chain files ==="

# Server chain for Envoy TLS serving: tls.crt = server + RA
cat "$PKI_DIR/server.crt" "$PKI_DIR/ra-intermediate.crt" > "$PKI_DIR/server-chain.crt"

# Full chain for requests verify: server-chain + root (used by SERVER_CHAIN in dashboard)
cat "$PKI_DIR/server.crt" "$PKI_DIR/ra-intermediate.crt" "$PKI_DIR/root-ca.crt" > "$PKI_DIR/full-chain.crt"

echo "  Server chain: $PKI_DIR/server-chain.crt"

echo ""
echo "=== 6. Deploy to target locations ==="

# Envoy TLS
cp "$PKI_DIR/server-chain.crt" "$ENVOY_TLS_DIR/tls.crt"
echo "  -> $ENVOY_TLS_DIR/tls.crt  (server + RA chain)"

cp "$PKI_DIR/server.key" "$ENVOY_TLS_DIR/tls.key"
echo "  -> $ENVOY_TLS_DIR/tls.key"

cp "$PKI_DIR/ra-intermediate.crt" "$ENVOY_TRUST_DIR/intermediate-ca.crt"
echo "  -> $ENVOY_TRUST_DIR/intermediate-ca.crt  (trusted CA for mTLS)"

# Dashboard/client files
cp "$PKI_DIR/client.crt" "$CERTS_DIR/client.crt"
echo "  -> $CERTS_DIR/client.crt"

cp "$PKI_DIR/client.key" "$CERTS_DIR/client.key"
echo "  -> $CERTS_DIR/client.key"

cp "$PKI_DIR/root-ca.crt" "$CERTS_DIR/root-ca.crt"
echo "  -> $CERTS_DIR/root-ca.crt  (trust anchor for dashboard verify)"

cp "$PKI_DIR/server-chain.crt" "$CERTS_DIR/server-chain.crt"
echo "  -> $CERTS_DIR/server-chain.crt"

cp "$PKI_DIR/ra-intermediate.crt" "$CERTS_DIR/intermediate-ca.crt"
echo "  -> $CERTS_DIR/intermediate-ca.crt"

echo ""
echo "=== 7. Compute SHA-256 thumbprint for Keycloak ==="
THUMBPRINT=$(openssl x509 -in "$PKI_DIR/client.crt" -outform DER | sha256sum | cut -d' ' -f1)
echo ""
echo "============================================================"
echo " NEW client cert thumbprint (SHA-256):"
echo "   $THUMBPRINT"
echo ""
echo " Update this value in:"
echo "   project_root/infra/keycloak/realm-export.json"
echo "   -> demo-client -> protocolMappers -> cnf-thumbprint ->"
echo "      claim.value -> x5t#S256"
echo "============================================================"

echo ""
echo "=== PKI generation complete! ==="
echo "Restart Docker stack and dashboard to apply."
