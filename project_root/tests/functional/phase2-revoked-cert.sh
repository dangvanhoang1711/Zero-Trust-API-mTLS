#!/usr/bin/env bash

set -euo pipefail

: "${ENVOY_URL:=https://localhost:8443}"
: "${REVOKED_CERT:=./fixtures/revoked-client.crt}"
: "${REVOKED_KEY:=./fixtures/revoked-client.key}"
: "${CA_CHAIN:=/etc/envoy/tls/trust/intermediate-ca.crt}"

if curl --silent --show-error \
  --cert "$REVOKED_CERT" \
  --key "$REVOKED_KEY" \
  --cacert "$CA_CHAIN" \
  "$ENVOY_URL/"; then
  printf 'expected revoked certificate handshake to fail\n' >&2
  exit 1
fi

printf 'revoked certificate rejected as expected\n'
