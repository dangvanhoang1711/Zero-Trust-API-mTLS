#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

: "${KEYCLOAK_BASE_URL:=https://localhost:18080}"
: "${KEYCLOAK_REALM:=zero-trust}"
: "${DEMO_CLIENT_SECRET:=demo-client-secret}"
: "${DEMO_MISMATCH_CLIENT_SECRET:=demo-client-mismatch-secret}"
: "${DEMO_DPOP_CLIENT_SECRET:=demo-client-dpop-secret}"
: "${KEYCLOAK_CONNECT_TIMEOUT:=3}"
: "${KEYCLOAK_MAX_TIME:=8}"
: "${CA_CERT:=$PROJECT_ROOT/envoy/certs/root-ca.crt}"

wait_for_keycloak() {
  local config_url="$KEYCLOAK_BASE_URL/realms/$KEYCLOAK_REALM/.well-known/openid-configuration"
  for _ in $(seq 1 120); do
    if curl --silent --show-error --fail --cacert "$CA_CERT" "$config_url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: Keycloak is not ready"
  return 1
}

get_access_token() {
  local client_id="$1"
  local client_secret
  local token_url="$KEYCLOAK_BASE_URL/realms/$KEYCLOAK_REALM/protocol/openid-connect/token"
  local response

  case "$client_id" in
    demo-client)
      client_secret="$DEMO_CLIENT_SECRET"
      ;;
    demo-client-mismatch)
      client_secret="$DEMO_MISMATCH_CLIENT_SECRET"
      ;;
    demo-client-dpop)
      client_secret="$DEMO_DPOP_CLIENT_SECRET"
      ;;
    *)
      echo "unsupported client_id: $client_id" >&2
      return 1
      ;;
  esac

  response=$(curl --silent --show-error --fail \
    --request POST \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --connect-timeout "$KEYCLOAK_CONNECT_TIMEOUT" \
    --max-time "$KEYCLOAK_MAX_TIME" \
    --cacert "$CA_CERT" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=$client_id" \
    --data-urlencode "client_secret=$client_secret" \
    "$token_url")

  python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"$response"
}

api_call_status() {
  local token="$1"
  local output_file="$2"

  : "${BASE_URL:=https://localhost:10000/}"
  : "${CLIENT_CERT:=$PROJECT_ROOT/envoy/certs/client-chain.crt}"
  : "${CLIENT_KEY:=$PROJECT_ROOT/envoy/certs/client.key}"
  : "${CA_CERT:=$PROJECT_ROOT/envoy/certs/root-ca.crt}"

  curl --silent --show-error \
    --connect-timeout "$KEYCLOAK_CONNECT_TIMEOUT" \
    --max-time "$KEYCLOAK_MAX_TIME" \
    --output "$output_file" \
    --write-out "%{http_code}" \
    --cert "$CLIENT_CERT" \
    --key "$CLIENT_KEY" \
    --cacert "$CA_CERT" \
    -H "Authorization: Bearer $token" \
    "$BASE_URL"
}
