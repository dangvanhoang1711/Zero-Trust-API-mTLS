#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

source "$SCRIPT_DIR/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CLIENT_CERT:=$PROJECT_ROOT/envoy/certs/client-chain.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/envoy/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/envoy/certs/root-ca.crt}"

echo "[CASE 3] Expect: 401 Unauthorized (invalid token)"

wait_for_keycloak

status_code=$(curl --silent --show-error \
  --output /tmp/zt_case3.out \
  --write-out "%{http_code}" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer invalid.token.value" \
  "$BASE_URL")

cat /tmp/zt_case3.out

if [ "$status_code" != "401" ]; then
  echo "FAIL: expected HTTP 401, got $status_code"
  exit 1
fi

echo "PASS: invalid-token request rejected"
