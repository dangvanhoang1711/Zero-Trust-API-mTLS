#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/lib-keycloak.sh"

echo "[CASE 4] Expect: 403 Forbidden (valid token, wrong cert binding)"

wait_for_keycloak
token=$(get_access_token "demo-client-mismatch")

status_code=$(api_call_status "$token" /tmp/zt_case4.out)

cat /tmp/zt_case4.out

if [ "$status_code" != "403" ]; then
  echo "FAIL: expected HTTP 403, got $status_code"
  exit 1
fi

echo "PASS: cert-binding mismatch rejected"
