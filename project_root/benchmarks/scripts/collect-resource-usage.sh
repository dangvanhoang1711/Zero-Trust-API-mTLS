#!/usr/bin/env bash

set -euo pipefail

: "${SAMPLE_INTERVAL:=1}"
SCENARIO="${1:?scenario name is required}"
duration_seconds="${2:-30}"
output_name="${3:-$SCENARIO-resource.csv}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
: "${RESULT_DIR:=$PROJECT_ROOT/benchmarks/results}"

mkdir -p "$RESULT_DIR"

OUTPUT_FILE="$RESULT_DIR/$output_name"

command -v docker >/dev/null 2>&1 || {
  echo "docker is required for resource sampling" >&2
  exit 1
}

if [ -z "$SAMPLE_INTERVAL" ] || [ "$SAMPLE_INTERVAL" -lt 1 ]; then
  SAMPLE_INTERVAL=1
fi

duration_seconds="$duration_seconds"
if [ -z "$duration_seconds" ] || [ "$duration_seconds" -lt 1 ]; then
  duration_seconds=30
fi

start_ts=$(date +%s)
end_ts=$((start_ts + duration_seconds))

echo "ts_unix_ms,scenario,container,cpu_percent,mem_usage,mem_limit,mem_percent,net_io,block_io,pids" > "$OUTPUT_FILE"

while [ "$(date +%s)" -lt "$end_ts" ]; do
  ts="$(date +%s%3N)"
  docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}},{{.BlockIO}},{{.PIDs}},{{.MemPerc}}' envoy ext_authz backend >/tmp/zt_stats.tmp || true
  while IFS=',' read -r container cpu mem net block pids memperc; do
    mem_usage="${mem%% / *}"
    mem_limit="${mem#* / }"
    echo "${ts},${SCENARIO},${container},${cpu},${mem_usage},${mem_limit},${memperc},${net},${block},${pids}" >> "$OUTPUT_FILE"
  done < /tmp/zt_stats.tmp
  sleep "$SAMPLE_INTERVAL"
done

rm -f /tmp/zt_stats.tmp

echo "Saved resource sample to: $OUTPUT_FILE"
