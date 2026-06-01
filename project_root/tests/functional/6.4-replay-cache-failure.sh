#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT_ROOT="$REPO_ROOT"
DOCKER_COMPOSE_FILE="$REPO_ROOT/../docker-compose.yml"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CLIENT_CERT:=$PROJECT_ROOT/infra/certs/client.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"
: "${EXT_AUTHZ_RECOVERY_WAIT_SECONDS:=8}"

compose() {
  docker-compose -f "$DOCKER_COMPOSE_FILE" "$@"
}

api_status() {
  local token="$1"
  local cert="$2"
  local key="$3"

  curl --silent --show-error \
    --output /tmp/zt_resilience_replay.out \
    --write-out "%{http_code}" \
    --cert "$cert" \
    --key "$key" \
    --cacert "$CA_CERT" \
    -H "Authorization: Bearer $token" \
    "$BASE_URL"
}

wait_for_api_with_token() {
  local token="$1"
  local cert="$2"
  local key="$3"

  for _ in $(seq 1 30); do
    local status
    status="$(api_status "$token" "$cert" "$key")"
    if [ "$status" = "200" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

echo "[RES-02] Replay cache failure behavior (in-memory cache reset on restart)"

wait_for_keycloak

TOKEN="$(get_access_token "demo-client")"

first_status="$(api_status "$TOKEN" "$CLIENT_CERT" "$CLIENT_KEY")"
if [ "$first_status" != "200" ]; then
  echo "FAIL: first request should pass, got $first_status"
  exit 1
fi

second_status="$(api_status "$TOKEN" "$CLIENT_CERT" "$CLIENT_KEY")"
if [ "$second_status" != "403" ]; then
  echo "FAIL: second request should be rejected as replay, got $second_status"
  exit 1
fi

compose restart ext_authz
sleep "$EXT_AUTHZ_RECOVERY_WAIT_SECONDS"

RECOVERY_TOKEN="$(get_access_token "demo-client")"
if ! wait_for_api_with_token "$RECOVERY_TOKEN" "$CLIENT_CERT" "$CLIENT_KEY"; then
  echo "FAIL: service did not recover after ext_authz restart"
  exit 1
fi

third_status="$(api_status "$TOKEN" "$CLIENT_CERT" "$CLIENT_KEY")"
if [ "$third_status" != "200" ]; then
  echo "FAIL: after ext_authz restart, replay cache reset should allow previously seen token"
  echo "      (this indicates external/restart-safe replay cache is not the only expected path)."
  exit 1
fi

echo "PASS: replay-cache fallback path observed (single-instance in-memory cache resets after restart)"
