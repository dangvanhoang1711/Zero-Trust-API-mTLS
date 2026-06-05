#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

source "$SCRIPT_DIR/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CA_CERT:=$PROJECT_ROOT/envoy/certs/root-ca.crt}"

echo "[CASE 2] Expect: 401 Unauthorized (missing token)"

wait_for_keycloak

status_code=$(curl --silent --show-error \
  --output /tmp/zt_case2.out \
  --write-out "%{http_code}" \
  --cert "$PROJECT_ROOT/envoy/certs/client-chain.crt" \
  --key "$PROJECT_ROOT/envoy/certs/client.key" \
  --cacert "$CA_CERT" \
  "$BASE_URL")

cat /tmp/zt_case2.out

if [ "$status_code" != "401" ]; then
  echo "FAIL: expected HTTP 401, got $status_code"
  exit 1
fi

echo "PASS: missing-token request rejected"
