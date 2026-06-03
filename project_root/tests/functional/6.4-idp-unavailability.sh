#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT_ROOT="$REPO_ROOT"
DOCKER_COMPOSE_FILE="$REPO_ROOT/../docker-compose.yml"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CLIENT_CERT:=$PROJECT_ROOT/infra/certs/client-chain.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"
: "${KEYCLOAK_OUTAGE_WAIT_SECONDS:=8}"

compose() {
  docker-compose -f "$DOCKER_COMPOSE_FILE" "$@"
}

api_status() {
  local token="$1"
  local cert="$2"
  local key="$3"
  local max_attempts="${IDP_UNAVAIL_API_TIMEOUT_SECONDS:-5}"

  curl --silent --show-error \
    --output /tmp/zt_resilience_idp.out \
    --write-out "%{http_code}" \
    --connect-timeout "$max_attempts" \
    --max-time "$max_attempts" \
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

echo "[RES-01] IdP unavailability while cached JWKS is present"

wait_for_keycloak

BASE_TOKEN="$(get_access_token "demo-client")"
CACHED_TOKEN="$(get_access_token "demo-client")"

base_status="$(api_status "$BASE_TOKEN" "$CLIENT_CERT" "$CLIENT_KEY")"
if [ "$base_status" != "200" ]; then
  echo "FAIL: baseline request did not pass, got $base_status"
  exit 1
fi

compose stop keycloak
sleep "$KEYCLOAK_OUTAGE_WAIT_SECONDS"

cached_status="$(api_status "$CACHED_TOKEN" "$CLIENT_CERT" "$CLIENT_KEY")"
if [ "$cached_status" != "200" ]; then
  echo "FAIL: cached token request should still pass during short IdP outage, got $cached_status"
  compose start keycloak >/dev/null
  exit 1
fi

if get_access_token "demo-client" >/tmp/zt_new_token.log 2>/tmp/zt_new_token.err; then
  echo "FAIL: token endpoint should be unavailable while Keycloak is stopped"
  compose start keycloak >/dev/null
  exit 1
fi

compose start keycloak >/dev/null
wait_for_keycloak

recovered_token="$(get_access_token "demo-client")"
if ! wait_for_api_with_token "$recovered_token" "$CLIENT_CERT" "$CLIENT_KEY"; then
  echo "FAIL: request did not recover after IdP restart"
  exit 1
fi

echo "PASS: IdP unavailability and recovery behavior verified"
