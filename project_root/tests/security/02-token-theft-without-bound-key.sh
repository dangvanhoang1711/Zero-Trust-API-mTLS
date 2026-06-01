#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${ATTACKER_CERT:=$PROJECT_ROOT/tests/functional/fixtures/valid-client.crt}"
: "${ATTACKER_KEY:=$PROJECT_ROOT/tests/functional/fixtures/valid-client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"

echo "[SEC-02] Expect: stolen token rejected without matching cert (403 Forbidden)"

wait_for_keycloak
token=$(get_access_token "demo-client")

status_code=$(curl --silent --show-error \
  --output /tmp/zt_sec02.out \
  --write-out "%{http_code}" \
  --cert "$ATTACKER_CERT" \
  --key "$ATTACKER_KEY" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $token" \
  "$BASE_URL")

if [ "$status_code" != "403" ]; then
  cat /tmp/zt_sec02.out
  echo "FAIL: expected 403 for token theft simulation, got $status_code" >&2
  exit 1
fi

echo "PASS: stolen-token scenario blocked"
