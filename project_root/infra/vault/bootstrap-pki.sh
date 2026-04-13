#!/usr/bin/env bash

set -euo pipefail

: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_TOKEN:?set VAULT_TOKEN}"

ROOT_PATH="${ROOT_PATH:-pki-root}"
INT_PATH="${INT_PATH:-pki-int}"
ROOT_COMMON_NAME="${ROOT_COMMON_NAME:-Zero Trust Root CA}"
INT_COMMON_NAME="${INT_COMMON_NAME:-Zero Trust Intermediate CA}"
VAULT_PUBLIC_ADDR="${VAULT_PUBLIC_ADDR:-https://vault.example.com:8200}"
OUTPUT_DIR="${OUTPUT_DIR:-./artifacts}"

mkdir -p "$OUTPUT_DIR"

vault secrets enable -path="$ROOT_PATH" pki || true
vault secrets tune -max-lease-ttl=87600h "$ROOT_PATH"

vault write -field=certificate "$ROOT_PATH/root/generate/internal" \
  common_name="$ROOT_COMMON_NAME" \
  issuer_name="zero-trust-root" \
  ttl=87600h > "$OUTPUT_DIR/root_ca.crt"

vault write "$ROOT_PATH/config/urls" \
  issuing_certificates="$VAULT_PUBLIC_ADDR/v1/$ROOT_PATH/ca" \
  crl_distribution_points="$VAULT_PUBLIC_ADDR/v1/$ROOT_PATH/crl"

vault secrets enable -path="$INT_PATH" pki || true
vault secrets tune -max-lease-ttl=43800h "$INT_PATH"

vault write -format=json "$INT_PATH/intermediate/generate/internal" \
  common_name="$INT_COMMON_NAME" \
  issuer_name="zero-trust-intermediate" > "$OUTPUT_DIR/intermediate.json"

jq -r '.data.csr' "$OUTPUT_DIR/intermediate.json" > "$OUTPUT_DIR/pki_int.csr"

vault write -format=json "$ROOT_PATH/root/sign-intermediate" \
  csr=@"$OUTPUT_DIR/pki_int.csr" \
  format=pem_bundle \
  ttl=43800h > "$OUTPUT_DIR/intermediate-signed.json"

jq -r '.data.certificate' "$OUTPUT_DIR/intermediate-signed.json" > "$OUTPUT_DIR/intermediate_ca.crt"
vault write "$INT_PATH/intermediate/set-signed" certificate=@"$OUTPUT_DIR/intermediate_ca.crt"

vault write "$INT_PATH/config/urls" \
  issuing_certificates="$VAULT_PUBLIC_ADDR/v1/$INT_PATH/ca" \
  crl_distribution_points="$VAULT_PUBLIC_ADDR/v1/$INT_PATH/crl"

vault write "$INT_PATH/roles/server-cert" \
  allowed_domains="envoy-service.default.svc.cluster.local" \
  allow_subdomains=true \
  max_ttl=24h \
  ttl=24h \
  key_type=rsa \
  key_bits=2048 \
  server_flag=true \
  client_flag=false

vault write "$INT_PATH/roles/client-cert" \
  allow_any_name=true \
  max_ttl=24h \
  ttl=24h \
  key_type=rsa \
  key_bits=2048 \
  server_flag=false \
  client_flag=true

vault write -format=json "$INT_PATH/issue/server-cert" \
  common_name="envoy-service.default.svc.cluster.local" \
  ttl=24h > "$OUTPUT_DIR/envoy-server.json"

jq -r '.data.certificate' "$OUTPUT_DIR/envoy-server.json" > "$OUTPUT_DIR/tls.crt"
jq -r '.data.private_key' "$OUTPUT_DIR/envoy-server.json" > "$OUTPUT_DIR/tls.key"

cat "$OUTPUT_DIR/intermediate_ca.crt" "$OUTPUT_DIR/root_ca.crt" > "$OUTPUT_DIR/chain.pem"
curl -fsS "$VAULT_ADDR/v1/$INT_PATH/crl/pem" -o "$OUTPUT_DIR/ca.crl"

cat <<EOF
PKI bootstrap complete.

Artifacts written to $OUTPUT_DIR:
- root_ca.crt
- intermediate_ca.crt
- tls.crt
- tls.key
- chain.pem
- ca.crl
EOF
