#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"

echo "[SEC-03] Expect: forged certificate blocked during TLS handshake"

wait_for_keycloak
token=$(get_access_token "demo-client")

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

forge_key="$workdir/fake-key.pem"
forge_cert="$workdir/fake-cert.pem"

openssl req -x509 -newkey rsa:2048 \
  -nodes \
  -keyout "$forge_key" \
  -out "$forge_cert" \
  -days 1 \
  -subj "/CN=fake-client" \
  -addext "subjectAltName = DNS:fake-client" \
  >/dev/null 2>&1

status_code=$(curl --silent --show-error \
  --output /tmp/zt_sec03.out \
  --write-out "%{http_code}" \
  --cert "$forge_cert" \
  --key "$forge_key" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $token" \
  "$BASE_URL" || true)

if [ "$status_code" != "000" ]; then
  if [ -s /tmp/zt_sec03.out ]; then
    cat /tmp/zt_sec03.out
  fi
  echo "FAIL: expected TLS handshake failure for forged cert, got HTTP $status_code" >&2
  exit 1
fi

printf 'forged certificate rejected as expected\n'
