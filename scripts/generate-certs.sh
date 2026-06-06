#!/bin/bash
set -euo pipefail

# === Zero-Trust PKI Certificate Generation ===
# Sets up Vault PKI engine, issues server + client certs, and deploys to envoy/certs/
# Usage: ./generate-certs.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PKI_DIR="$PROJECT_ROOT/vault/artifacts"
CERTS_DIR="$PROJECT_ROOT/envoy/certs"
ENVOY_TRUST_DIR="$CERTS_DIR/trust"
KEYCLOAK_DIR="$PROJECT_ROOT/keycloak"
VAULT_SCRIPTS="$PROJECT_ROOT/vault/scripts"
COMPOSE_FILE="$PROJECT_ROOT/infrastructure/docker/docker-compose.private.yml"

: "${VAULT_ADDR:=https://localhost:8200}"
: "${VAULT_TOKEN:=root}"
: "${VAULT_CACERT:=$CERTS_DIR/vault-ca.crt}"
: "${KEYCLOAK_URL:=https://localhost:18080}"
: "${KEYCLOAK_CA_CERT:=$CERTS_DIR/root-ca.crt}"
: "${KEYCLOAK_ADMIN:=admin}"
: "${KEYCLOAK_ADMIN_PASSWORD:=admin}"
: "${SERVER_CERT_DNS_NAMES:=localhost,envoy,backend,protected-api,ext-authz,keycloak}"
: "${SERVER_CERT_IP_SANS:=127.0.0.1}"
: "${SERVER_CERT_EXTRA_DNS:=}"
: "${SERVER_CERT_EXTRA_IP_SANS:=}"

mkdir -p "$PKI_DIR" "$CERTS_DIR" "$ENVOY_TRUST_DIR"

export VAULT_ADDR VAULT_TOKEN VAULT_CACERT
export KEYCLOAK_URL KEYCLOAK_CA_CERT KEYCLOAK_ADMIN KEYCLOAK_ADMIN_PASSWORD

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

info() {
  log "INFO: $*"
}

err() {
  log "ERROR: $*"
}

vault_cmd() {
  if command -v vault >/dev/null 2>&1; then
    vault "$@"
    return
  fi

  docker compose -f "$COMPOSE_FILE" exec -T \
    -e VAULT_ADDR="https://127.0.0.1:8200" \
    -e VAULT_CACERT="/certs/vault-ca.crt" \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    vault vault "$@"
}

vault_status() {
  vault_cmd status >/dev/null 2>&1
}

thumbprint_for_cert() {
  local cert_path="$1"

  openssl x509 -in "$cert_path" -outform DER \
    | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
}

if [ -n "$SERVER_CERT_EXTRA_DNS" ]; then
  SERVER_CERT_DNS_NAMES="$SERVER_CERT_DNS_NAMES,$SERVER_CERT_EXTRA_DNS"
fi

if [ -n "$SERVER_CERT_EXTRA_IP_SANS" ]; then
  SERVER_CERT_IP_SANS="$SERVER_CERT_IP_SANS,$SERVER_CERT_EXTRA_IP_SANS"
fi

# --- 1. Wait for Vault ---
info "=== 1. Wait for Vault ==="
for i in $(seq 1 30); do
  if vault_status; then
    info "  Vault ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    err "Vault not reachable at $VAULT_ADDR after 30 seconds"
    exit 1
  fi
  sleep 1
done

# --- 2. Root CA ---
info "=== 2. Root CA (pki-root engine, self-signed, 10yr) ==="
vault_cmd secrets enable -path=pki-root pki 2>/dev/null || true
vault_cmd secrets tune -max-lease-ttl=87600h pki-root

if ! vault_cmd read pki-root/issuer/zero-trust-root >/dev/null 2>&1; then
  vault_cmd write -field=certificate pki-root/root/generate/internal \
    common_name="Zero Trust Root CA" \
    issuer_name="zero-trust-root" \
    ttl=87600h > "$PKI_DIR/root-ca.crt"
  info "  Root CA created"
else
  info "  Root CA already exists, fetching..."
  vault_cmd read -field=certificate pki-root/issuer/zero-trust-root > "$PKI_DIR/root-ca.crt"
fi

vault_cmd write pki-root/config/urls \
  issuing_certificates="https://vault:8200/v1/pki-root/ca" \
  crl_distribution_points="https://vault:8200/v1/pki-root/crl" 2>/dev/null || true

# --- 3. RA Intermediate CA ---
info "=== 3. RA Intermediate CA (pki-int engine, 5yr) ==="
vault_cmd secrets enable -path=pki-int pki 2>/dev/null || true
vault_cmd secrets tune -max-lease-ttl=43800h pki-int

if ! vault_cmd read pki-int/issuer/zero-trust-ra >/dev/null 2>&1; then
  vault_cmd write -format=json pki-int/intermediate/generate/internal \
    common_name="Zero Trust RA Intermediate CA" \
    issuer_name="zero-trust-ra" \
    ttl=43800h > "$PKI_DIR/intermediate.json"

  python3 -c "import json,sys;d=json.load(open('$PKI_DIR/intermediate.json'));print(d['data']['csr'])" > "$PKI_DIR/intermediate.csr"

  vault_cmd write -format=json pki-root/root/sign-intermediate \
    csr=- \
    format=pem_bundle \
    ttl=43800h < "$PKI_DIR/intermediate.csr" > "$PKI_DIR/intermediate-signed.json"

  python3 -c "import json,sys;d=json.load(open('$PKI_DIR/intermediate-signed.json'));print(d['data']['certificate'])" > "$PKI_DIR/ra-intermediate.crt"
  vault_cmd write pki-int/intermediate/set-signed certificate=- < "$PKI_DIR/ra-intermediate.crt"
  info "  RA Intermediate CA created"
else
  info "  RA Intermediate CA already exists, fetching..."
  vault_cmd read -field=certificate pki-int/issuer/zero-trust-ra > "$PKI_DIR/ra-intermediate.crt" 2>/dev/null || true
fi

vault_cmd write pki-int/config/urls \
  issuing_certificates="https://vault:8200/v1/pki-int/ca" \
  crl_distribution_points="https://vault:8200/v1/pki-int/crl" 2>/dev/null || true

# --- 4. Create roles ---
info "=== 4. Create PKI roles ==="
vault_cmd write pki-int/roles/server-cert \
  allow_any_name=true \
  max_ttl=730h \
  ttl=730h \
  key_type=ec \
  key_bits=256 \
  server_flag=true \
  client_flag=false 2>/dev/null || info "  Role 'server-cert' already exists"

vault_cmd write pki-int/roles/client-cert \
  allow_any_name=true \
  max_ttl=730h \
  ttl=730h \
  key_type=ec \
  key_bits=256 \
  server_flag=false \
  client_flag=true 2>/dev/null || info "  Role 'client-cert' already exists"

# --- 5. Issue server cert ---
info "=== 5. Issue server cert ==="
info "  DNS SANs: $SERVER_CERT_DNS_NAMES"
info "  IP SANs:  $SERVER_CERT_IP_SANS"
vault_cmd write -format=json pki-int/issue/server-cert \
  common_name="localhost" \
  alt_names="$SERVER_CERT_DNS_NAMES" \
  ip_sans="$SERVER_CERT_IP_SANS" \
  ttl=730h > "$PKI_DIR/server.json"

python3 -c "import json,sys;d=json.load(open('$PKI_DIR/server.json'));print(d['data']['certificate'])" > "$PKI_DIR/server.crt"
python3 -c "import json,sys;d=json.load(open('$PKI_DIR/server.json'));print(d['data']['private_key'])" > "$PKI_DIR/server.key"
info "  Server cert issued"

# --- 6. Issue client cert ---
info "=== 6. Issue client cert ==="
vault_cmd write -format=json pki-int/issue/client-cert \
  common_name="demo-client" \
  ttl=730h > "$PKI_DIR/client.json"

python3 -c "import json,sys;d=json.load(open('$PKI_DIR/client.json'));print(d['data']['certificate'])" > "$PKI_DIR/client.crt"
python3 -c "import json,sys;d=json.load(open('$PKI_DIR/client.json'));print(d['data']['private_key'])" > "$PKI_DIR/client.key"
info "  Client cert issued"

# --- 7. Issue rotated client cert ---
info "=== 7. Issue rotated client cert ==="
vault_cmd write -format=json pki-int/issue/client-cert \
  common_name="attacker-client" \
  ttl=730h > "$PKI_DIR/attacker-client.json"

python3 -c "import json,sys;d=json.load(open('$PKI_DIR/attacker-client.json'));print(d['data']['certificate'])" > "$PKI_DIR/attacker-client.crt"
python3 -c "import json,sys;d=json.load(open('$PKI_DIR/attacker-client.json'));print(d['data']['private_key'])" > "$PKI_DIR/attacker-client.key"
info "  Rotated client cert issued"

# --- 8. Extract issuing CA ---
info "=== 8. Extract issuing CA chain ==="
python3 -c "
import json
d = json.load(open('$PKI_DIR/server.json'))
issuing_ca = d['data']['issuing_ca']
ca_chain = d['data']['ca_chain']
with open('$PKI_DIR/issuing-ca.crt', 'w') as f:
    f.write(issuing_ca.strip() + '\n')
with open('$PKI_DIR/ca-chain.crt', 'w') as f:
    for cert in ca_chain:
        f.write(cert.strip() + '\n')
"

python3 -c "
import json
d = json.load(open('$PKI_DIR/client.json'))
client_issuing_ca = d['data']['issuing_ca']
with open('$PKI_DIR/client-issuing-ca.crt', 'w') as f:
    f.write(client_issuing_ca.strip() + '\n')
"

# --- 9. Build chain files ---
info "=== 9. Build chain files ==="
cat "$PKI_DIR/server.crt" > "$PKI_DIR/server-chain.crt"
echo "" >> "$PKI_DIR/server-chain.crt"
cat "$PKI_DIR/issuing-ca.crt" >> "$PKI_DIR/server-chain.crt"

cat "$PKI_DIR/client.crt" > "$PKI_DIR/client-chain.crt"
echo "" >> "$PKI_DIR/client-chain.crt"
cat "$PKI_DIR/client-issuing-ca.crt" >> "$PKI_DIR/client-chain.crt"

cat "$PKI_DIR/attacker-client.crt" > "$PKI_DIR/attacker-client-chain.crt"
echo "" >> "$PKI_DIR/attacker-client-chain.crt"
cat "$PKI_DIR/client-issuing-ca.crt" >> "$PKI_DIR/attacker-client-chain.crt"

# --- 10. Deploy to envoy/certs/ ---
info "=== 10. Deploy certificates to envoy/certs/ ==="
cp "$PKI_DIR/server-chain.crt" "$CERTS_DIR/server-chain.crt"
cp "$PKI_DIR/server.crt"       "$CERTS_DIR/server.crt"
cp "$PKI_DIR/server.key"       "$CERTS_DIR/server.key"
cp "$PKI_DIR/root-ca.crt"      "$CERTS_DIR/root-ca.crt"
cp "$PKI_DIR/ca-chain.crt"     "$CERTS_DIR/ca-chain.crt"
cp "$PKI_DIR/issuing-ca.crt"   "$CERTS_DIR/intermediate-ca.crt"
cp "$PKI_DIR/client-chain.crt" "$CERTS_DIR/client-chain.crt"
cp "$PKI_DIR/client.crt"       "$CERTS_DIR/client.crt"
cp "$PKI_DIR/client.key"       "$CERTS_DIR/client.key"
cp "$PKI_DIR/attacker-client-chain.crt" "$CERTS_DIR/attacker-client-chain.crt"
cp "$PKI_DIR/attacker-client.crt"       "$CERTS_DIR/attacker-client.crt"
cp "$PKI_DIR/attacker-client.key"       "$CERTS_DIR/attacker-client.key"

# Also deploy to trust directory for Envoy
cp "$PKI_DIR/root-ca.crt"      "$ENVOY_TRUST_DIR/root-ca.crt"
cp "$PKI_DIR/ca-chain.crt"     "$ENVOY_TRUST_DIR/intermediate-ca.crt"

# Legacy compatibility: also copy to tls.crt/tls.key
cp "$PKI_DIR/server-chain.crt" "$CERTS_DIR/tls.crt"
cp "$PKI_DIR/server.key"       "$CERTS_DIR/tls.key"
cp "$PKI_DIR/root-ca.crt"      "$CERTS_DIR/ca.crt"

info "  Certificates deployed to $CERTS_DIR/"

# --- 11. Compute thumbprints ---
info "=== 11. Compute SHA-256 thumbprints ==="
THUMBPRINT="$(thumbprint_for_cert "$PKI_DIR/client.crt")"
MISMATCH_THUMBPRINT="$(thumbprint_for_cert "$PKI_DIR/attacker-client.crt")"
info "  Client cert thumbprint: $THUMBPRINT"
info "  Rotated client cert thumbprint: $MISMATCH_THUMBPRINT"

# --- 12. Generate realm-export.json with correct thumbprints ---
info "=== 12. Generate realm-export.json ==="
TEMPLATE="$KEYCLOAK_DIR/realm-export.json.template"
if [ -f "$TEMPLATE" ]; then
  sed "s/__CLIENT_CERT_THUMBPRINT__/$THUMBPRINT/g; s/__CLIENT_MISMATCH_THUMBPRINT__/$MISMATCH_THUMBPRINT/g" \
    "$TEMPLATE" > "$KEYCLOAK_DIR/realm-export.json"
  info "  Generated realm-export.json with correct thumbprint"
else
  info "  Template not found at $TEMPLATE, skipping realm generation"
fi

# --- 13. Update Keycloak thumbprints via Admin REST API ---
info "=== 13. Update Keycloak thumbprints ==="
if [ -f "$VAULT_SCRIPTS/update_keycloak_thumbprint.py" ]; then
  if python3 "$VAULT_SCRIPTS/update_keycloak_thumbprint.py" "$THUMBPRINT" demo-client cnf-thumbprint; then
    info "  Updated demo-client thumbprint"
  else
    info "  WARN: demo-client thumbprint update failed"
  fi

  if python3 "$VAULT_SCRIPTS/update_keycloak_thumbprint.py" \
    "$MISMATCH_THUMBPRINT" demo-client-mismatch cnf-thumbprint-mismatch; then
    info "  Updated demo-client-mismatch thumbprint"
  else
    info "  WARN: demo-client-mismatch thumbprint update failed"
  fi
else
  info "  update_keycloak_thumbprint.py not found, skipping"
fi

info "=== PKI generation complete ==="
