#!/usr/bin/env bash

set -euo pipefail

: "${ENVOY_URL:=https://localhost:8443}"
: "${CLIENT_CERT:=/var/run/tls/client/tls.crt}"
: "${CLIENT_KEY:=/var/run/tls/client/tls.key}"
: "${CA_CHAIN:=/etc/envoy/tls/trust/intermediate-ca.crt}"

curl --silent --show-error --fail \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --cacert "$CA_CHAIN" \
  "$ENVOY_URL/"
