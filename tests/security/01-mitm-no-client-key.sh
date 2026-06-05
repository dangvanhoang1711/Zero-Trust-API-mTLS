#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$PROJECT_ROOT/scripts/clients/curl-scripts/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CA_CERT:=$PROJECT_ROOT/envoy/certs/root-ca.crt}"

echo "[SEC-01] Expect: TLS handshake blocked (no client key/cert)"

wait_for_keycloak
token=$(get_access_token "demo-client")

status_code=$(curl --silent --show-error \
  --output /tmp/zt_sec01.out \
  --write-out "%{http_code}" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $token" \
  "$BASE_URL" || true)

if [ "$status_code" != "000" ]; then
  if [ -s /tmp/zt_sec01.out ]; then
    cat /tmp/zt_sec01.out
  fi
  echo "FAIL: expected TLS handshake failure without client cert, got HTTP $status_code" >&2
  exit 1
fi

printf 'MITM without client key blocked at TLS layer\n'
