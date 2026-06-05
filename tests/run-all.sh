#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BASE_URL="${BASE_URL:-https://localhost:10000/}"
CLIENT_CERT="${CLIENT_CERT:-$PROJECT_ROOT/envoy/certs/client-chain.crt}"
CLIENT_KEY="${CLIENT_KEY:-$PROJECT_ROOT/envoy/certs/client.key}"
CA_CERT="${CA_CERT:-$PROJECT_ROOT/envoy/certs/root-ca.crt}"

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

echo "=========================================="
echo "Running Zero-Trust Security Test Suite"
echo "=========================================="

run_test() {
  local name="$1"
  local script="$2"
  
  echo ""
  echo "==> $name"
  "$script"
}

run_test "Test A: Valid mTLS certificate + valid bound JWT → 200 OK" \
  "$PROJECT_ROOT/scripts/clients/curl-scripts/01-ok-mtls-valid-header.sh"

run_test "Test B: Missing bearer token → 401 Unauthorized" \
  "$PROJECT_ROOT/scripts/clients/curl-scripts/02-fail-no-cert.sh"

run_test "Test C: Invalid bearer token → 401 Unauthorized" \
  "$PROJECT_ROOT/scripts/clients/curl-scripts/03-fail-invalid-auth-header.sh"

run_test "Test D: Valid token with wrong cnf.x5t#S256 binding → 403 Forbidden" \
  "$PROJECT_ROOT/scripts/clients/curl-scripts/04-fail-valid-token-wrong-cert-binding.sh"

run_test "Test E: Replay same JWT jti → second request 403 Forbidden" \
  "$PROJECT_ROOT/scripts/clients/curl-scripts/05-fail-replay-jti.sh"
run_test "Test F: Expired client certificate → TLS handshake failure" \
  "$PROJECT_ROOT/tests/functional/phase2-expired-cert.sh"
run_test "Test G: Revoked client certificate → TLS handshake failure" \
  "$PROJECT_ROOT/tests/functional/phase2-revoked-cert.sh"
run_test "Test H: Algorithm downgrade attempt (alg: none) → 401 Unauthorized" \
  "$PROJECT_ROOT/tests/functional/phase2-alg-none.sh"

echo ""
echo "=========================================="
echo "✓ All security tests passed"
echo "=========================================="
