#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BASE_URL="${BASE_URL:-https://localhost:10000/}"
CLIENT_CERT="${CLIENT_CERT:-$PROJECT_ROOT/infra/certs/client.crt}"
CLIENT_KEY="${CLIENT_KEY:-$PROJECT_ROOT/infra/certs/client.key}"
CA_CERT="${CA_CERT:-$PROJECT_ROOT/infra/certs/root-ca.crt}"

echo "Waiting for Envoy endpoint to be ready..."
ready="false"
for _ in $(seq 1 30); do
  if curl --silent --show-error \
    --output /dev/null \
    --cert "$CLIENT_CERT" \
    --key "$CLIENT_KEY" \
    --cacert "$CA_CERT" \
    -H "x-test-auth: ok" \
    "$BASE_URL"; then
    ready="true"
    break
  fi
  sleep 1
done

if [ "$ready" != "true" ]; then
  echo "FAIL: Envoy endpoint is not ready after 30 seconds"
  exit 1
fi

"$PROJECT_ROOT/clients/curl-scripts/01-ok-mtls-valid-header.sh"
"$PROJECT_ROOT/clients/curl-scripts/02-fail-no-cert.sh"
"$PROJECT_ROOT/clients/curl-scripts/03-fail-invalid-auth-header.sh"
"$PROJECT_ROOT/clients/curl-scripts/04-fail-valid-token-wrong-cert-binding.sh"
"$PROJECT_ROOT/clients/curl-scripts/05-fail-replay-jti.sh"

echo "All MVP demo tests passed"
