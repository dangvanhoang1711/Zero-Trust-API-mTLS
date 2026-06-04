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
# Or: VAULT_ADDR + VAULT_TOKEN env vars (e.g. http://vault:8200 + root)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"  # = project_root/ (parent of infra/)

PKI_DIR="$PROJECT_ROOT/infra/pki-vault"
CERTS_DIR="$PROJECT_ROOT/infra/certs"
ENVOY_TLS_DIR="$PROJECT_ROOT/envoy_config/tls"
ENVOY_TRUST_DIR="$ENVOY_TLS_DIR/trust"
VAULT_CONTAINER="zero-trust-mvp-vault-1"

mkdir -p "$PKI_DIR" "$CERTS_DIR" "$ENVOY_TLS_DIR" "$ENVOY_TRUST_DIR"

VAULT() {
  if command -v vault > /dev/null 2>&1 && [ -n "${VAULT_ADDR:-}" ]; then
    vault "$@"
  else
    docker exec -i -e VAULT_TOKEN=root "$VAULT_CONTAINER" vault "$@"
  fi
}

VAULT_STATUS() {
  if command -v vault > /dev/null 2>&1 && [ -n "${VAULT_ADDR:-}" ]; then
    vault status > /dev/null 2>&1
  else
    docker exec "$VAULT_CONTAINER" vault status > /dev/null 2>&1
  fi
}

echo "=== 1. Wait for Vault ==="
for i in $(seq 1 30); do
  if VAULT_STATUS; then
    echo "  Vault ready"
    break
  fi
  sleep 1
done

echo ""
echo "=== 2. Root CA (pki-root engine, self-signed, 10yr) ==="
VAULT secrets enable -path=pki-root pki 2>/dev/null || true
VAULT secrets tune -max-lease-ttl=87600h pki-root

if ! VAULT read pki-root/issuer/zero-trust-root > /dev/null 2>&1; then
  VAULT write -field=certificate pki-root/root/generate/internal \
    common_name="Zero Trust Root CA" \
    issuer_name="zero-trust-root" \
    ttl=87600h > "$PKI_DIR/root-ca.crt"
  echo "  Root CA: $PKI_DIR/root-ca.crt (created)"
else
  echo "  Root CA already exists, fetching existing cert..."
  VAULT read -field=certificate pki-root/issuer/zero-trust-root > "$PKI_DIR/root-ca.crt"
  echo "  Root CA: $PKI_DIR/root-ca.crt (fetched existing)"
fi

VAULT write pki-root/config/urls \
  issuing_certificates="http://vault:8200/v1/pki-root/ca" \
  crl_distribution_points="http://vault:8200/v1/pki-root/crl" 2>/dev/null || true

echo ""
echo "=== 3. RA Intermediate CA (pki-int engine, 5yr, signed by Root) ==="
VAULT secrets enable -path=pki-int pki 2>/dev/null || true
VAULT secrets tune -max-lease-ttl=43800h pki-int

if ! VAULT read pki-int/issuer/zero-trust-ra > /dev/null 2>&1; then
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
  echo "  RA Intermediate CA created"
else
  echo "  RA Intermediate CA already exists, fetching existing cert..."
  VAULT read -field=certificate pki-int/issuer/zero-trust-ra > "$PKI_DIR/ra-intermediate.crt" 2>/dev/null || true
  echo "  RA Intermediate CA: $PKI_DIR/ra-intermediate.crt (fetched existing)"
fi

VAULT write pki-int/config/urls \
  issuing_certificates="http://vault:8200/v1/pki-int/ca" \
  crl_distribution_points="http://vault:8200/v1/pki-int/crl" 2>/dev/null || true
echo "  RA Intermediate CA: $PKI_DIR/ra-intermediate.crt"

echo ""
echo "=== 4. Create roles ==="
VAULT write pki-int/roles/server-cert \
  allow_any_name=true \
  max_ttl=730h \
  ttl=730h \
  key_type=ec \
  key_bits=256 \
  server_flag=true \
  client_flag=false 2>/dev/null || echo "  Role 'server-cert' already exists, skipping"

VAULT write pki-int/roles/client-cert \
  allow_any_name=true \
  max_ttl=730h \
  ttl=730h \
  key_type=ec \
  key_bits=256 \
  server_flag=false \
  client_flag=true 2>/dev/null || echo "  Role 'client-cert' already exists, skipping"

echo ""
echo "=== 5. Issue server cert (CN=localhost) ==="
VAULT write -format=json pki-int/issue/server-cert \
  common_name="localhost" \
  alt_names="localhost,envoy,backend,protected-api,ext-authz,envoy-service.default.svc.cluster.local${CERT_SAN_DNS:+,$CERT_SAN_DNS}" \
  ip_sans="127.0.0.1${CERT_SAN_IP:+,$CERT_SAN_IP}" \
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
echo "=== 7. Extract issuing CA from Vault server response ==="
python3 -c "
import json
d = json.load(open('$PKI_DIR/server.json'))
issuing_ca = d['data']['issuing_ca']
ca_chain = d['data']['ca_chain']
# issuing_ca is the RA cert that actually signed the server cert
with open('$PKI_DIR/issuing-ca.crt', 'w') as f:
    f.write(issuing_ca.strip() + '\n')
# ca_chain[0] is issuing_ca, ca_chain[1] is root CA
with open('$PKI_DIR/ca-chain.crt', 'w') as f:
    for cert in ca_chain:
        f.write(cert.strip() + '\n')
print('  Issuing CA saved: $PKI_DIR/issuing-ca.crt')
print('  Full CA chain saved: $PKI_DIR/ca-chain.crt')
"

echo ""
echo "=== 8. Build chain files ==="
echo "$(cat "$PKI_DIR/server.crt")" > "$PKI_DIR/server-chain.crt"
echo "" >> "$PKI_DIR/server-chain.crt"
echo "$(cat "$PKI_DIR/issuing-ca.crt")" >> "$PKI_DIR/server-chain.crt"

python3 -c "
import json
d = json.load(open('$PKI_DIR/client.json'))
client_issuing_ca = d['data']['issuing_ca']
with open('$PKI_DIR/client-issuing-ca.crt', 'w') as f:
    f.write(client_issuing_ca.strip() + '\n')
print('  Client issuing CA saved: $PKI_DIR/client-issuing-ca.crt')
"

echo "$(cat "$PKI_DIR/client.crt")" > "$PKI_DIR/client-chain.crt"
echo "" >> "$PKI_DIR/client-chain.crt"
echo "$(cat "$PKI_DIR/client-issuing-ca.crt")" >> "$PKI_DIR/client-chain.crt"
echo "  Client chain: $PKI_DIR/client-chain.crt"

echo ""
echo "=== 9. Deploy to target locations ==="
cat "$PKI_DIR/server-chain.crt" > "$ENVOY_TLS_DIR/tls.crt"
echo "  -> $ENVOY_TLS_DIR/tls.crt  (server + issuing CA chain)"

cat "$PKI_DIR/server.key" > "$ENVOY_TLS_DIR/tls.key"
echo "  -> $ENVOY_TLS_DIR/tls.key"

cat "$PKI_DIR/root-ca.crt" > "$ENVOY_TRUST_DIR/root-ca.crt"
echo "  -> $ENVOY_TRUST_DIR/root-ca.crt  (Root CA trust anchor for Envoy)"

cat "$PKI_DIR/ca-chain.crt" > "$ENVOY_TRUST_DIR/intermediate-ca.crt"
echo "  -> $ENVOY_TRUST_DIR/intermediate-ca.crt  (CA chain for mTLS client verification)"

cat "$PKI_DIR/client-chain.crt" > "$CERTS_DIR/client-chain.crt"
echo "  -> $CERTS_DIR/client-chain.crt  (client cert + issuing CA for --cert)"

cat "$PKI_DIR/client.crt" > "$CERTS_DIR/client.crt"
echo "  -> $CERTS_DIR/client.crt  (leaf only)"

cat "$PKI_DIR/client.key" > "$CERTS_DIR/client.key"
echo "  -> $CERTS_DIR/client.key"

cat "$PKI_DIR/root-ca.crt" > "$CERTS_DIR/root-ca.crt"
echo "  -> $CERTS_DIR/root-ca.crt  (trust anchor)"

cat "$PKI_DIR/server-chain.crt" > "$CERTS_DIR/server-chain.crt"
echo "  -> $CERTS_DIR/server-chain.crt"

cat "$PKI_DIR/issuing-ca.crt" > "$CERTS_DIR/intermediate-ca.crt"
echo "  -> $CERTS_DIR/intermediate-ca.crt  (issuing CA for client verification)"

cat "$PKI_DIR/ca-chain.crt" > "$CERTS_DIR/ca-chain.crt"
echo "  -> $CERTS_DIR/ca-chain.crt  (full CA chain for ext_authz trust bundle)"

echo ""
echo "=== 10. Compute SHA-256 thumbprint for Keycloak ==="
THUMBPRINT=$(openssl x509 -in "$PKI_DIR/client.crt" -outform DER | sha256sum | cut -d' ' -f1)
echo "  Thumbprint: $THUMBPRINT"

# Compute a different thumbprint for the mismatch client (all zeros placeholder)
# The mismatch test verifies that a wrong thumbprint is rejected
MISMATCH_THUMBPRINT="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

echo ""
echo "=== 11. Generate realm-export.json with correct thumbprint ==="
sed "s/__CLIENT_CERT_THUMBPRINT__/$THUMBPRINT/g; s/__CLIENT_MISMATCH_THUMBPRINT__/$MISMATCH_THUMBPRINT/g" \
  "$PROJECT_ROOT/infra/keycloak/realm-export.json.template" > "$PROJECT_ROOT/infra/keycloak/realm-export.json"
echo "  Generated realm-export.json with correct thumbprint"

echo ""
echo "=== 12. Update thumbprint in Keycloak via Admin REST API ==="
python3 "$SCRIPT_DIR/update_keycloak_thumbprint.py" "$THUMBPRINT" && \
  echo "  Keycloak thumbprint updated successfully (no restart needed)" || \
  echo "  WARN: Keycloak update failed. Update manually in realm-export.json"

echo ""
echo "=== 13. Configure Keycloak to use ES256 (ECDSA) signing ==="
ADMIN_TOKEN=$(curl -sf -X POST "http://keycloak:8080/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=${KEYCLOAK_ADMIN:-admin}&password=${KEYCLOAK_ADMIN_PASSWORD:-admin}" \
  2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])" 2>/dev/null || true)

if [ -n "$ADMIN_TOKEN" ]; then
  # Check if ECDSA key provider already exists
  EC_KEY_EXISTS=$(curl -sf -X GET "http://keycloak:8080/admin/realms/zero-trust/components?name=ecdsa-generated" \
    -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null | python3 -c "import json,sys;print(len(json.load(sys.stdin))>0)" 2>/dev/null || echo "false")

  if [ "$EC_KEY_EXISTS" != "True" ]; then
    echo "  Creating ECDSA key provider..."
    curl -sf -X POST "http://keycloak:8080/admin/realms/zero-trust/components" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "ecdsa-generated",
        "providerId": "ecdsa-generated",
        "providerType": "org.keycloak.keys.KeyProvider",
        "parentId": "zero-trust",
        "config": {
          "priority": ["100"],
          "algorithm": ["ES256"],
          "ecdsaEllipticCurveKey": ["P-256"],
          "enabled": ["true"],
          "active": ["true"]
        }
      }' > /dev/null 2>&1 && echo "  ECDSA key provider created" || echo "  WARN: Failed to create ECDSA key provider"
  else
    echo "  ECDSA key provider already exists"
  fi

  echo "  Setting defaultSignatureAlgorithm to ES256..."
  REALM_CONFIG=$(curl -sf -X GET "http://keycloak:8080/admin/realms/zero-trust" \
    -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null)
  if [ -n "$REALM_CONFIG" ]; then
    echo "$REALM_CONFIG" | python3 -c "
import json,sys
data = json.load(sys.stdin)
data['defaultSignatureAlgorithm'] = 'ES256'
print(json.dumps(data))
" | curl -sf -X PUT "http://keycloak:8080/admin/realms/zero-trust" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d @- > /dev/null 2>&1 && echo "  defaultSignatureAlgorithm set to ES256" || echo "  WARN: Failed to set ES256"
  fi
else
  echo "  WARN: Cannot get admin token — ES256 config skipped"
fi

echo ""
echo "=== Vault PKI generation complete! ==="
