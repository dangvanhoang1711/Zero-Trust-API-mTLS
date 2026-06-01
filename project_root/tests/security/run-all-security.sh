#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

run_security_test() {
  local name="$1"
  local script="$2"

  echo ""
  echo "==> $name"
  "$script"
}

echo "=========================================="
echo "Running Zero-Trust Security Attack Scenarios"
echo "=========================================="

run_security_test "SEC-01: MITM/replay without client cert/key" \
  "$PROJECT_ROOT/tests/security/01-mitm-no-client-key.sh"
run_security_test "SEC-02: Token theft simulation (stolen token + non-bound cert)" \
  "$PROJECT_ROOT/tests/security/02-token-theft-without-bound-key.sh"
run_security_test "SEC-03: Certificate forgery (self-signed client certificate)" \
  "$PROJECT_ROOT/tests/security/03-certificate-forgery.sh"
run_security_test "SEC-04: Signature forgery (tampered JWT)" \
  "$PROJECT_ROOT/tests/security/04-signature-forgery-jwt.sh"

echo ""
echo "=========================================="
echo "✓ Security scenario tests passed"
echo "=========================================="
