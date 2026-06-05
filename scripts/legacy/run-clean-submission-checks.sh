#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT_ROOT="$REPO_ROOT/project_root"

ROOT_COMPOSE="$REPO_ROOT/docker-compose.yml"

resolve_compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      echo "docker compose"
      return 0
    fi
  fi

  return 1
}

wait_for_envoy() {
  echo "Waiting for Envoy endpoint to become available..."
  if ! source "$PROJECT_ROOT/scripts/clients/curl-scripts/lib-keycloak.sh" >/dev/null 2>&1; then
    echo "WARN: cannot source keycloak helper script; skipping wait_for_keycloak verification."
  else
    for _ in $(seq 1 60); do
      if wait_for_keycloak >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
  fi

  for _ in $(seq 1 60); do
    if curl --silent --show-error --fail \
      --cert "$PROJECT_ROOT/envoy/certs/client-chain.crt" \
      --key "$PROJECT_ROOT/envoy/certs/client.key" \
      --cacert "$PROJECT_ROOT/envoy/certs/root-ca.crt" \
      -H "x-test-auth: ok" \
      "https://localhost:10000/" > /dev/null; then
      return
    fi
    sleep 2
  done

  echo "WARN: service readiness timeout. Logs may be inspected before tests continue."
}

run_suite() {
  local cmd="$1"
  echo
  echo "==> $cmd"
  bash -c "$cmd"
}

main() {
  COMPOSE_CMD="$(resolve_compose_cmd || true)"
  if [ -z "$COMPOSE_CMD" ]; then
    echo "ERROR: docker compose command not available."
    echo "Install Docker or Docker Compose before running this script."
    exit 1
  fi

  if [ ! -f "$ROOT_COMPOSE" ]; then
    echo "ERROR: missing compose file at $ROOT_COMPOSE"
    exit 1
  fi

  echo "==> clean prep: stop any prior stack from root compose"
  $COMPOSE_CMD -f "$ROOT_COMPOSE" down -v --remove-orphans || true

  echo "==> starting services (root runtime stack)"
  $COMPOSE_CMD -f "$ROOT_COMPOSE" up --build -d

  wait_for_envoy

  run_suite "cd \"$PROJECT_ROOT\" && ./tests/run-all.sh"
  run_suite "cd \"$PROJECT_ROOT\" && ./tests/security/run-all-security.sh"
  run_suite "cd \"$PROJECT_ROOT/tests/functional\" && ./run-all-resilience.sh"
}

cleanup() {
  local rc=$?

  if [ -n "${COMPOSE_CMD:-}" ]; then
    echo
    echo "==> cleanup: stopping root stack"
    $COMPOSE_CMD -f "$ROOT_COMPOSE" down -v --remove-orphans || true
  fi

  return $rc
}

trap cleanup EXIT
main "$@"
