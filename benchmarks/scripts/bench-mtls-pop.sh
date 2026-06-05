#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$PROJECT_ROOT/clients/curl-scripts/lib-keycloak.sh"
source "$SCRIPT_DIR/bench-common.sh"

: "${BASE_URL:=https://localhost:10000/}"
: "${RESULT_DIR:=$PROJECT_ROOT/benchmarks/results}"
: "${RESULT_FILE:=$RESULT_DIR/mtls-pop-latency.csv}"

mkdir -p "$RESULT_DIR"

wait_for_keycloak
TOKEN="$(get_access_token "demo-client")"

run_benchmark \
  "mtls-pop" \
  "$BASE_URL" \
  "$TOKEN" \
  "" \
  1 \
  "$RESULT_FILE"

print_summary_banner "$RESULT_FILE"
