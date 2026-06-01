#!/bin/bash
set -euo pipefail

# === Zero-Trust PKI Hierarchy via HashiCorp Vault ===
#
#   Root CA  (Vault pki-root engine, self-signed, 10yr)
#     └── signs ──► RA Intermediate CA (Vault pki-int engine, 5yr)
#                     ├── signs ──► Server cert (Envoy, CN=localhost)
#                     └── signs ──► Client cert (CN=demo-client)
#
# Requires: docker container zero-trust-mvp-vault-1 running

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"  # = project_root/ (parent of infra/)
PKI_DIR="$PROJECT_ROOT/infra/pki-vault"
CERTS_DIR="$PROJECT_ROOT/infra/certs"
ENVOY_TLS_DIR="$PROJECT_ROOT/envoy_config/tls"
ENVOY_TRUST_DIR="$ENVOY_TLS_DIR/trust"
VAULT_CONTAINER="zero-trust-mvp-vault-1"

mkdir -p "$PKI_DIR" "$CERTS_DIR" "$ENVOY_TLS_DIR" "$ENVOY_TRUST_DIR"

VAULT() {
  docker exec -i -e VAULT_TOKEN=root "$VAULT_CONTAINER" vault "$@"
}

echo "=== 1. Wait for Vault ==="
for i in $(seq 1 30); do
  if docker exec "$VAULT_CONTAINER" vault status > /dev/null 2>&1; then
    echo "  Vault ready"
    break
  fi
  sleep 1
done

echo ""
echo "=== 2. Root CA (pki-root engine, self-signed, 10yr) ==="
VAULT secrets enable -path=pki-root pki 2>/dev/null || true
VAULT secrets tune -max-lease-ttl=87600h pki-root

VAULT write -field=certificate pki-root/root/generate/internal \
  common_name="Zero Trust Root CA" \
  issuer_name="zero-trust-root" \
  ttl=87600h > "$PKI_DIR/root-ca.crt"
echo "  Root CA: $PKI_DIR/root-ca.crt"

VAULT write pki-root/config/urls \
  issuing_certificates="http://vault:8200/v1/pki-root/ca" \
  crl_distribution_points="http://vault:8200/v1/pki-root/crl"

echo ""
echo "=== 3. RA Intermediate CA (pki-int engine, 5yr, signed by Root) ==="
VAULT secrets enable -path=pki-int pki 2>/dev/null || true
VAULT secrets tune -max-lease-ttl=43800h pki-int

VAULT write -format=json pki-int/intermediate/generate/internal \
  common_name="Zero Trust RA Intermediate CA" \
  issuer_name="zero-trust-ra" \
  ttl=43800h > "$PKI_DIR/intermediate.json"

python3 -c "import json,sys;d=json.load(open('$PKI_DIR/intermediate.json'));print(d['data']['csr'])" > "$PKI_DIR/intermediate.csr"

VAULT write -format=json pki-root/root/sign-intermediate \
  csr=- \
  format=pem_bundle \
  ttl=43800h < "$PKI_DIR/intermediate.csr" > "$PKI_DIR/intermediate-signed.json"

python3 -c "import json,sys;d=json.load(open('$PKI_DIR/intermediate-signed.json'));print(d['data']['certificate'])" > "$PKI_DIR/ra-intermediate.crt"
VAULT write pki-int/intermediate/set-signed certificate=- < "$PKI_DIR/ra-intermediate.crt"

VAULT write pki-int/config/urls \
  issuing_certificates="http://vault:8200/v1/pki-int/ca" \
  crl_distribution_points="http://vault:8200/v1/pki-int/crl"
echo "  RA Intermediate CA: $PKI_DIR/ra-intermediate.crt"

echo ""
echo "=== 4. Create roles ==="
VAULT write pki-int/roles/server-cert \
  allow_any_name=true \
  max_ttl=730h \
  ttl=730h \
  key_type=rsa \
  key_bits=2048 \
  server_flag=true \
  client_flag=false

VAULT write pki-int/roles/client-cert \
  allow_any_name=true \
  max_ttl=730h \
  ttl=730h \
  key_type=rsa \
  key_bits=2048 \
  server_flag=false \
  client_flag=true

echo ""
echo "=== 5. Issue server cert (CN=localhost) ==="
VAULT write -format=json pki-int/issue/server-cert \
  common_name="localhost" \
  alt_names="localhost,envoy-service.default.svc.cluster.local" \
  ip_sans="127.0.0.1" \
  ttl=730h > "$PKI_DIR/server.json"

python3 -c "import json,sys;d=json.load(open('$PKI_DIR/server.json'));print(d['data']['certificate'])" > "$PKI_DIR/server.crt"
python3 -c "import json,sys;d=json.load(open('$PKI_DIR/server.json'));print(d['data']['private_key'])" > "$PKI_DIR/server.key"
echo "  Server cert: $PKI_DIR/server.crt"

echo ""
echo "=== 6. Issue client cert (CN=demo-client) ==="
VAULT write -format=json pki-int/issue/client-cert \
  common_name="demo-client" \
  ttl=730h > "$PKI_DIR/client.json"

python3 -c "import json,sys;d=json.load(open('$PKI_DIR/client.json'));print(d['data']['certificate'])" > "$PKI_DIR/client.crt"
python3 -c "import json,sys;d=json.load(open('$PKI_DIR/client.json'));print(d['data']['private_key'])" > "$PKI_DIR/client.key"
echo "  Client cert: $PKI_DIR/client.crt"

echo ""
echo "=== 7. Build chain files ==="
cat "$PKI_DIR/server.crt" "$PKI_DIR/ra-intermediate.crt" > "$PKI_DIR/server-chain.crt"

echo ""
echo "=== 8. Deploy to target locations ==="
cp "$PKI_DIR/server-chain.crt" "$ENVOY_TLS_DIR/tls.crt"
echo "  -> $ENVOY_TLS_DIR/tls.crt  (server + RA chain)"

cp "$PKI_DIR/server.key" "$ENVOY_TLS_DIR/tls.key"
echo "  -> $ENVOY_TLS_DIR/tls.key"

cp "$PKI_DIR/ra-intermediate.crt" "$ENVOY_TRUST_DIR/intermediate-ca.crt"
echo "  -> $ENVOY_TRUST_DIR/intermediate-ca.crt  (trusted CA for mTLS)"

cp "$PKI_DIR/client.crt" "$CERTS_DIR/client.crt"
echo "  -> $CERTS_DIR/client.crt"

cp "$PKI_DIR/client.key" "$CERTS_DIR/client.key"
echo "  -> $CERTS_DIR/client.key"

cp "$PKI_DIR/root-ca.crt" "$CERTS_DIR/root-ca.crt"
echo "  -> $CERTS_DIR/root-ca.crt  (trust anchor)"

cp "$PKI_DIR/server-chain.crt" "$CERTS_DIR/server-chain.crt"
echo "  -> $CERTS_DIR/server-chain.crt"

cp "$PKI_DIR/ra-intermediate.crt" "$CERTS_DIR/intermediate-ca.crt"
echo "  -> $CERTS_DIR/intermediate-ca.crt"

echo ""
echo "=== 9. Compute SHA-256 thumbprint for Keycloak ==="
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
echo "=== Vault PKI generation complete! ==="
echo "Restart Docker stack and dashboard to apply."
