#!/usr/bin/env bash

set -euo pipefail

: "${ENVOY_URL:=https://localhost:8443}"
: "${EXPIRED_CERT:=./fixtures/expired-client.crt}"
: "${EXPIRED_KEY:=./fixtures/expired-client.key}"
: "${CA_CHAIN:=/etc/envoy/tls/trust/intermediate-ca.crt}"

if curl --silent --show-error \
  --cert "$EXPIRED_CERT" \
  --key "$EXPIRED_KEY" \
  --cacert "$CA_CHAIN" \
  "$ENVOY_URL/"; then
  printf 'expected expired certificate handshake to fail\n' >&2
  exit 1
fi

printf 'expired certificate rejected as expected\n'
