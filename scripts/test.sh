#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${LOG_FILE:-$PROJECT_ROOT/tests/test-output.log}"

BASE_URL="${BASE_URL:-https://localhost:10000/}"
CLIENT_CERT="${CLIENT_CERT:-$PROJECT_ROOT/envoy/certs/client-chain.crt}"
CLIENT_KEY="${CLIENT_KEY:-$PROJECT_ROOT/envoy/certs/client.key}"
CA_CERT="${CA_CERT:-$PROJECT_ROOT/envoy/certs/root-ca.crt}"

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

info() {
  log "INFO: $*"
}

err() {
  log "ERROR: $*"
}

passed() {
  log "PASS: $*"
}

failed() {
  log "FAIL: $*"
}

export BASE_URL CLIENT_CERT CLIENT_KEY CA_CERT

check_endpoint() {
  local name="$1"
  local url="$2"
  local max_retries="${3:-5}"
  shift 3

  for _ in $(seq 1 "$max_retries"); do
    if curl --silent --show-error --output /dev/null --max-time 5 "$@" "$url" 2>/dev/null; then
      passed "$name is healthy"
      return 0
    fi
    sleep 2
  done

  failed "$name is not responding at $url"
  return 1
}

health_check() {
  info "=== Service Health Checks ==="
  local status=0

  check_endpoint "Envoy HTTPS" "https://localhost:10001/health" 5 --cacert "$CA_CERT" || status=1
  check_endpoint "Backend" "https://localhost:8000/health" 5 --cacert "$CA_CERT" || status=1
  check_endpoint "Keycloak" "https://localhost:18080/realms/master/.well-known/openid-configuration" 5 --cacert "$CA_CERT" || status=1
  check_endpoint "Vault" "https://localhost:8200/v1/sys/health" 5 --cacert "$PROJECT_ROOT/envoy/certs/vault-ca.crt" || status=1

  if command -v redis-cli >/dev/null 2>&1; then
    if redis-cli -h localhost -p 6379 ping >/dev/null 2>&1; then
      passed "Redis is healthy"
    else
      failed "Redis is not responding on localhost:6379"
      status=1
    fi
  fi

  if [ "$status" -ne 0 ]; then
    err "Some services are unhealthy. Check docker compose logs."
    return 1
  fi
}

run_unit_tests() {
  info "=== Unit Tests ==="
  local status=0

  if [ -d "$PROJECT_ROOT/backend/tests" ]; then
    info "Running backend unit tests..."
    if ! (cd "$PROJECT_ROOT/backend" && python3 -m unittest discover -s tests -v); then
      err "backend unit tests failed"
      status=1
    fi
  fi

  if [ -d "$PROJECT_ROOT/ext_authz" ]; then
    if command -v go >/dev/null 2>&1; then
      info "Running ext-authz unit tests..."
      if ! (cd "$PROJECT_ROOT/ext_authz" && go test ./... -v -count=1); then
        err "ext-authz unit tests failed"
        status=1
      fi
    else
      info "Go not installed, skipping ext-authz unit tests"
    fi
  fi

  return "$status"
}

run_integration_tests() {
  info "=== Integration / Security Tests ==="
  local test_suite="$PROJECT_ROOT/tests/run-all.sh"

  if [ ! -f "$test_suite" ]; then
    info "$test_suite not found"
    return 0
  fi

  info "Running full test suite: $test_suite"
  bash "$test_suite"
}

run_security_tests() {
  info "=== Security Attack Scenario Tests ==="
  local test_suite="$PROJECT_ROOT/tests/security/run-all-security.sh"

  if [ ! -f "$test_suite" ]; then
    info "$test_suite not found"
    return 0
  fi

  info "Running security tests: $test_suite"
  bash "$test_suite"
}

run_functional_tests() {
  info "=== Functional / Resilience Tests ==="
  local test_suite="$PROJECT_ROOT/tests/functional/run-all-resilience.sh"

  if [ ! -f "$test_suite" ]; then
    info "$test_suite not found"
    return 0
  fi

  info "Running functional tests: $test_suite"
  bash "$test_suite"
}

main() {
  local mode="${1:---all}"
  local exit_code=0

  info "=== Zero-Trust Test Runner ==="
  info "Mode: $mode"
  info "Log: $LOG_FILE"
  echo

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

  echo
  if [ "$exit_code" -eq 0 ]; then
    info "All tests passed"
  else
    err "Some tests failed (exit code $exit_code)"
  fi

  exit "$exit_code"
}

main "$@"
