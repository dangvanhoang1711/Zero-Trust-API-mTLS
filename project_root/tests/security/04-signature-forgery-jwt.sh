#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CLIENT_CERT:=$PROJECT_ROOT/infra/certs/client-chain.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"

echo "[SEC-04] Expect: JWT signature forgery rejected (401 Unauthorized)"

wait_for_keycloak
token=$(get_access_token "demo-client")

IFS='.' read -r token_header token_payload token_sig <<< "$token"
if [ -z "${token_sig:-}" ]; then
  echo "FAIL: failed to parse token" >&2
  exit 1
fi

if [ "${token_sig: -1}" = "A" ]; then
  forged_sig="${token_sig%?}B"
else
  forged_sig="${token_sig%?}A"
fi
forged_token="${token_header}.${token_payload}.${forged_sig}"

status_code=$(curl --silent --show-error \
  --output /tmp/zt_sec04.out \
  --write-out "%{http_code}" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $forged_token" \
  "$BASE_URL")

if [ "$status_code" != "401" ]; then
  cat /tmp/zt_sec04.out
  echo "FAIL: expected 401 for forged JWT, got $status_code" >&2
  exit 1
fi

echo "PASS: forged signature JWT rejected"
