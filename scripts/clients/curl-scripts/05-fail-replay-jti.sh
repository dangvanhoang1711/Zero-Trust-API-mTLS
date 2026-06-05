#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/lib-keycloak.sh"

echo "[CASE 5] Expect: first 200, second 403 (replay jti)"

wait_for_keycloak
token=$(get_access_token "demo-client")

first_status=$(api_call_status "$token" /tmp/zt_case5_first.out)
second_status=$(api_call_status "$token" /tmp/zt_case5_second.out)

echo "first response:" && cat /tmp/zt_case5_first.out
echo "second response:" && cat /tmp/zt_case5_second.out

if [ "$first_status" != "200" ]; then
  echo "FAIL: expected first request HTTP 200, got $first_status"
  exit 1
fi

if [ "$second_status" != "403" ]; then
  echo "FAIL: expected replay request HTTP 403, got $second_status"
  exit 1
fi

echo "PASS: replay request blocked"
