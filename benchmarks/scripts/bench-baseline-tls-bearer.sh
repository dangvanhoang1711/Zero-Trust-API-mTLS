#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"
source "$SCRIPT_DIR/bench-common.sh"

: "${BASE_URL:=https://localhost:10001/}"
: "${RESULT_DIR:=$PROJECT_ROOT/benchmarks/results}"
: "${RESULT_FILE:=$RESULT_DIR/baseline-latency.csv}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"

mkdir -p "$RESULT_DIR"

if [ ! -f "$CA_CERT" ]; then
  echo "INFO: This is a baseline profile; handshake may fail if mTLS is required."
fi

wait_for_keycloak
TOKEN="$(get_access_token "demo-client")"

run_benchmark \
  "baseline" \
  "$BASE_URL" \
  "$TOKEN" \
  "" \
  0 \
  "$RESULT_FILE"

print_summary_banner "$RESULT_FILE"
