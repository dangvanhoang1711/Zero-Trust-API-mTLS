#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_resilience_test() {
  local name="$1"
  local script="$2"
  echo ""
  echo "==> $name"
  "$script"
}

echo "==============================================="
echo "Running Zero-Trust Operational Resilience Suite"
echo "==============================================="

run_resilience_test "6.4.1: Certificate rotation (zero-downtime smoke)" \
  "$SCRIPT_DIR/6.4-cert-rotation.sh"
run_resilience_test "6.4.2: JWKS rotation smoke check" \
  "$SCRIPT_DIR/6.4-jwks-rotation.sh"
run_resilience_test "6.4.3: Keycloak unavailability behavior" \
  "$SCRIPT_DIR/6.4-idp-unavailability.sh"
run_resilience_test "6.4.4: Replay cache failure simulation" \
  "$SCRIPT_DIR/6.4-replay-cache-failure.sh"

echo ""
echo "==============================================="
echo "✓ Operational resilience scripts completed"
echo "==============================================="
