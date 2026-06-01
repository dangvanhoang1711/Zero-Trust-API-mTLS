#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

: "${REQUESTS:=200}"
: "${CONCURRENCY:=1}"
: "${RESULT_DIR:=$PROJECT_ROOT/benchmarks/results}"
: "${INCLUDE_RESOURCE_SAMPLING:=1}"
: "${SAMPLE_INTERVAL:=1}"
: "${SAMPLING_DURATION:=$((REQUESTS / 10 + 10))}"

mkdir -p "$RESULT_DIR"
SUMMARY_FILE="$RESULT_DIR/benchmark-summary.csv"
export RESULT_DIR

if [ ! -f "$SUMMARY_FILE" ]; then
  echo "scenario,total_requests,success,fail,avg_sec,min_sec,max_sec,throughput_rps,reject_403,reject_403_ratio" > "$SUMMARY_FILE"
fi

run_profile() {
  local profile="$1"
  local result_file="$2"
  local script="$3"
  local resource_file="$4"
  local result_path="$RESULT_DIR/$result_file"
  local sampler_pid

  if [ "$INCLUDE_RESOURCE_SAMPLING" = "1" ]; then
    ("$SCRIPT_DIR/collect-resource-usage.sh" \
      "$profile" \
      "$SAMPLING_DURATION" \
      "$resource_file") &
    sampler_pid=$!
    sleep 1
  else
    sampler_pid=""
  fi

  REQUESTS=$REQUESTS CONCURRENCY=$CONCURRENCY \
    RESULT_FILE="$RESULT_DIR/$result_file" \
    "$SCRIPT_DIR/$script"

  if [ -n "${sampler_pid:-}" ]; then
    wait "$sampler_pid" || true
  fi

  append_summary_csv_row "$result_path" "$profile" "$SUMMARY_FILE"
}

echo "[bench] Running baseline (TLS-only path with bearer token only)"
run_profile "baseline" "baseline-latency.csv" "bench-baseline-tls-bearer.sh" "baseline-resource.csv"

echo "[bench] Running mTLS-only (valid cert, invalid token)"
run_profile "mtls-only" "mtls-only-latency.csv" "bench-mtls-only.sh" "mtls-only-resource.csv"

echo "[bench] Running mTLS + PoP (valid cert + valid token)"
run_profile "mtls-pop" "mtls-pop-latency.csv" "bench-mtls-pop.sh" "mtls-pop-resource.csv"

cat <<EOF
[bench] Benchmark CSV outputs:
  - $RESULT_DIR/baseline-latency.csv
  - $RESULT_DIR/mtls-only-latency.csv
  - $RESULT_DIR/mtls-pop-latency.csv
  - $SUMMARY_FILE
  - resource usage files with suffix "-resource.csv"
  - replay-hit ratio (403 ratio) included in each row of $SUMMARY_FILE
EOF
