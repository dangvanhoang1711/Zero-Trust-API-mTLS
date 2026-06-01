#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT_ROOT="$REPO_ROOT"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CLIENT_CERT:=$PROJECT_ROOT/infra/certs/client.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"
: "${ROTATED_CLIENT_CERT:=""}"
: "${ROTATED_CLIENT_KEY:=""}"
: "${ROTATED_TOKEN_CLIENT:=demo-client-mismatch}"

api_status() {
  local token="$1"
  local cert="$2"
  local key="$3"

  curl --silent --show-error \
    --output /tmp/zt_resilience_rotation.out \
    --write-out "%{http_code}" \
    --cert "$cert" \
    --key "$key" \
    --cacert "$CA_CERT" \
    -H "Authorization: Bearer $token" \
    "$BASE_URL"
}

if [ -z "$ROTATED_CLIENT_CERT" ] || [ -z "$ROTATED_CLIENT_KEY" ]; then
  echo "SKIP: set ROTATED_CLIENT_CERT and ROTATED_CLIENT_KEY to run cert-rotation scenario."
  echo "      Example: ROTATED_CLIENT_CERT=/path/client_new.crt ROTATED_CLIENT_KEY=/path/client_new.key"
  exit 0
fi

echo "[RES-03] Certificate rotation scenario (zero-downtime smoke test)"
echo "      rotated cert: $ROTATED_CLIENT_CERT"
echo "      rotated key:  $ROTATED_CLIENT_KEY"

wait_for_keycloak

old_token="$(get_access_token "demo-client")"
old_status="$(api_status "$old_token" "$CLIENT_CERT" "$CLIENT_KEY")"
if [ "$old_status" != "200" ]; then
  echo "FAIL: baseline token should succeed before rotation, got $old_status"
  exit 1
fi

new_token="$(get_access_token "$ROTATED_TOKEN_CLIENT")"
new_status="$(api_status "$new_token" "$ROTATED_CLIENT_CERT" "$ROTATED_CLIENT_KEY")"
if [ "$new_status" != "200" ]; then
  echo "FAIL: rotated certificate + token should succeed, got $new_status"
  exit 1
fi

echo "PASS: certificate rotation smoke request succeeds without gateway restart"
