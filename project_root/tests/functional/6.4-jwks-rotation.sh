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
: "${JWK_ROTATION_CMD:=}"

api_status() {
  local token="$1"

  curl --silent --show-error \
    --output /tmp/zt_resilience_jwks.out \
    --write-out "%{http_code}" \
    --cert "$CLIENT_CERT" \
    --key "$CLIENT_KEY" \
    --cacert "$CA_CERT" \
    -H "Authorization: Bearer $token" \
    "$BASE_URL"
}

if [ -z "$JWK_ROTATION_CMD" ]; then
  echo "SKIP: set JWK_ROTATION_CMD to rotate Keycloak signing keys and then verify post-rotation behavior."
  echo "      Example: JWK_ROTATION_CMD=\"docker-compose -f docker-compose.yml exec keycloak /opt/keycloak/bin/kcadm.sh ...\""
  exit 0
fi

echo "[RES-04] JWKS rotation scenario"

wait_for_keycloak
token_before="$(get_access_token "demo-client")"
status_before="$(api_status "$token_before")"
if [ "$status_before" != "200" ]; then
  echo "FAIL: baseline request before rotation failed: $status_before"
  exit 1
fi

if ! bash -c "$JWK_ROTATION_CMD"; then
  echo "FAIL: JWKS rotation command failed"
  exit 1
fi

sleep 5

status_after_rotation="$(api_status "$token_before")"
if [ "$status_after_rotation" != "200" ]; then
  echo "WARN: old token was rejected after rotation (this can happen if old keys are removed)."
  echo "      If this is expected for your deployment, treat as environment-dependent behavior."
fi

token_after="$(get_access_token "demo-client")"
status_after_new="$(api_status "$token_after")"
if [ "$status_after_new" != "200" ]; then
  echo "FAIL: new token was not accepted after JWKS rotation, got $status_after_new"
  exit 1
fi

echo "PASS: JWKS rotation command executed and post-rotation token validation succeeded"
