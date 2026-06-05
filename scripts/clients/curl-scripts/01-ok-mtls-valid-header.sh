#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CLIENT_CERT:=$PROJECT_ROOT/infra/certs/client-chain.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"

echo "[CASE 1] Expect: 200 OK (mTLS + valid Keycloak JWT + cert binding)"

wait_for_keycloak
token=$(get_access_token "demo-client")

status_code=$(curl --silent --show-error \
  --output /tmp/zt_case1.out \
  --write-out "%{http_code}" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $token" \
  "$BASE_URL")

cat /tmp/zt_case1.out

if [ "$status_code" != "200" ]; then
  echo "FAIL: expected HTTP 200, got $status_code"
  exit 1
fi

echo
echo "PASS: request allowed"
