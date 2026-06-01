#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR" && pwd)"

: "${ENVOY_URL:=https://localhost:10000/}"
: "${REVOKED_CERT:=$PROJECT_ROOT/fixtures/revoked-client.crt}"
: "${REVOKED_KEY:=$PROJECT_ROOT/fixtures/revoked-client.key}"
: "${CA_CHAIN:=$PROJECT_ROOT/fixtures/chain.pem}"

status_code=$(curl --silent --show-error \
  --cert "$REVOKED_CERT" \
  --key "$REVOKED_KEY" \
  --cacert "$CA_CHAIN" \
  --output /tmp/zt_case_g.out \
  --write-out "%{http_code}" \
  "$ENVOY_URL" || true)

if [ "$status_code" = "200" ]; then
  echo "expected revoked certificate request to be blocked, but request unexpectedly succeeded" >&2
  exit 1
fi

if [ "$status_code" != "000" ]; then
  cat /tmp/zt_case_g.out
fi

printf 'revoked certificate rejected as expected\n'
