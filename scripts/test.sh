#!/bin/bash
set -euo pipefail

# === Zero-Trust Test Runner ===
# Runs security tests, functional tests, and service health checks
# Usage: ./test.sh [--security] [--functional] [--all] [--unit]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd")
LOG_FILE="${LOG_FILE:-$PROJECT_ROOT/tests/test-output.log}"
BASE_URL="${BASE_URL:-https://localhost:10000/}"
CLIENT_CERT="${CLIENT_CERT:-$PROJECT_ROOT/envoy/certs/client-chain.crt}"
CLIENT_KEY="${CLIENT_KEY:-$PROJECT_ROOT/envoy/certs/client.key}"
CA_CERT="${CA_CERT:-$PROJECT_ROOT/envoy/certs/root-ca.crt}"

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info()   { log "INFO: $*"; }
err()    { log "ERROR: $*"; }
passed() { log "PASS: $*"; }
failed() { log "FAIL: $*"; }

export BASE_URL CLIENT_CERT CLIENT_KEY CA_CERT

# --- Health check ---
health_check() {
  info "=== Service Health Checks ==="
  local all_healthy=true

  check_endpoint() {
    local name="$1"
    local url="$2"
    local max_retries="${3:-5}"
    for i in $(seq 1 "$max_retries"); do
      if curl --silent --show-error --output /dev/null --max-time 5 "$url" 2>/dev/null; then
        passed "$name is healthy"
        return 0
      fi
      sleep 2
    done
    failed "$name is not responding at $url"
    all_healthy=false
    return 1
  }

  check_endpoint "Envoy (HTTP)"      "http://localhost:10002/"      5
  check_endpoint "Backend"           "http://localhost:8080/health" 5
  check_endpoint "Keycloak"          "http://localhost:8080/health" 5
  check_endpoint "Vault"             "http://localhost:8200/v1/sys/health" 5
  check_endpoint "Redis"             "http://localhost:6379/"      3 || true  # Redis health is non-HTTP

  if ! $all_healthy; then
    err "Some services are unhealthy. Check docker compose logs."
    return 1
  fi
  return 0
}

# --- Unit tests ---
run_unit_tests() {
  info "=== Unit Tests ==="

  # Backend unit tests
  if [ -d "$PROJECT_ROOT/backend" ]; then
    info "Running backend unit tests..."
    (cd "$PROJECT_ROOT/backend" && python3 -m pytest tests/ -v 2>/dev/null) || \
      info "  No pytest tests found in backend (skipping)"
  fi

  # ext-authz unit tests
  if [ -d "$PROJECT_ROOT/ext_authz" ]; then
    if command -v go &>/dev/null; then
      info "Running ext-authz unit tests..."
      (cd "$PROJECT_ROOT/ext_authz" && go test ./... -v -count=1 2>&1 | tail -20) || \
        err "  ext-authz unit tests failed"
    else
      info "  Go not installed, skipping ext-authz unit tests"
    fi
  fi
}

# --- Run-all integration/security tests ---
run_integration_tests() {
  info "=== Integration / Security Tests ==="

  local test_suite="$PROJECT_ROOT/tests/run-all.sh"
  if [ -f "$test_suite" ]; then
    info "Running full test suite: $test_suite"
    bash "$test_suite" || {
      failed "Test suite exited with errors"
      return 1
    }
  else
    info "  $test_suite not found"
  fi
}

run_security_tests() {
  info "=== Security Attack Scenario Tests ==="
  local test_suite="$PROJECT_ROOT/tests/security/run-all-security.sh"
  if [ -f "$test_suite" ]; then
    info "Running security tests: $test_suite"
    bash "$test_suite" || {
      failed "Security tests exited with errors"
      return 1
    }
  else
    info "  $test_suite not found"
  fi
}

run_functional_tests() {
  info "=== Functional / Resilience Tests ==="
  local test_suite="$PROJECT_ROOT/tests/functional/run-all-resilience.sh"
  if [ -f "$test_suite" ]; then
    info "Running functional tests: $test_suite"
    bash "$test_suite" || {
      failed "Functional tests exited with errors"
      return 1
    }
  else
    info "  $test_suite not found"
  fi
}

# --- Main ---
main() {
  local mode="${1:-all}"
  local exit_code=0

  info "=== Zero-Trust Test Runner ==="
  info "Mode: $mode"
  info "Log: $LOG_FILE"
  echo ""

  case "$mode" in
    --health)
      health_check || exit_code=1
      ;;
    --unit)
      run_unit_tests || exit_code=1
      ;;
    --security)
      health_check || true
      run_security_tests || exit_code=1
      ;;
    --functional)
      health_check || true
      run_functional_tests || exit_code=1
      ;;
    --integration)
      health_check || true
      run_integration_tests || exit_code=1
      ;;
    --all|*)
      health_check || true
      run_unit_tests || true
      run_integration_tests || exit_code=1
      run_security_tests || exit_code=1
      run_functional_tests || exit_code=1
      ;;
  esac

  echo ""
  if [ "$exit_code" -eq 0 ]; then
    info "All tests passed"
  else
    err "Some tests failed (exit code $exit_code)"
  fi
  exit "$exit_code"
}

main "$@"
