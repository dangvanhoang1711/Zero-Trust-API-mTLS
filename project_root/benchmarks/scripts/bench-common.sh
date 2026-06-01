#!/usr/bin/env bash

set -euo pipefail

: "${BASE_URL:=https://localhost:10000/}"
: "${PROJECT_ROOT:=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
: "${CLIENT_CERT:=$PROJECT_ROOT/infra/certs/client.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"
: "${REQUESTS:=200}"
: "${CONCURRENCY:=1}"
: "${METHOD:=GET}"

if [ ! -f "$CA_CERT" ]; then
  echo "WARN: CA certificate not found: $CA_CERT" >&2
fi

if [ "${CONCURRENCY:-1}" -lt 1 ]; then
  echo "CONCURRENCY must be >= 1" >&2
  exit 1
fi

request_json() {
  local label="$1"
  local request_id="$2"
  local url="$3"
  local cert="$4"
  local key="$5"
  local token="$6"
  local header="$7"
  local output_file="$8"
  local temp_body
  local status_line
  local status elapsed size

  temp_body="$(mktemp)"
  trap 'rm -f "$temp_body"' RETURN

  local curl_opts=(
    --silent
    --show-error
    --output "$temp_body"
    --write-out "%{http_code},%{time_total},%{size_download}"
    --retry 2
    --max-time 8
    --connect-timeout 5
  )

  if [ -n "$cert" ] && [ -n "$key" ]; then
    curl_opts+=(--cert "$cert" --key "$key")
  fi
  if [ -n "$CA_CERT" ]; then
    curl_opts+=(--cacert "$CA_CERT")
  fi
  if [ -n "$token" ]; then
    header="Authorization: Bearer $token"
  fi
  if [ -n "$header" ]; then
    curl_opts+=(-H "$header")
  fi

  status_line="$(curl "${curl_opts[@]}" "$METHOD" "$url" || true)"
  if [ -z "$status_line" ]; then
    status_line="000,0,0"
  fi
  if ! IFS=',' read -r status elapsed size <<< "$status_line"; then
    status="000"
    elapsed="0"
    size="0"
  fi

  local size_bytes="$size"
  size_bytes="$(printf "%s" "$size_bytes" | sed 's/[^0-9.]//g')"
  if [ -z "$size_bytes" ]; then
    size_bytes=0
  fi

  printf '%s,%s,%s,%.3f,%s\n' \
    "$label" "$request_id" "$status" "$elapsed" "$size_bytes" >> "$output_file"
}

positive_int() {
  local raw_value="$1"
  local fallback="$2"
  local value

  value="$(printf "%s" "$raw_value" | tr -cd '0-9')"
  if [ -z "$value" ] || [ "$value" -lt 1 ]; then
    printf "%s\n" "$fallback"
    return
  fi

  printf "%s\n" "$value"
}

append_csv_header() {
  local output_file="$1"
  if [ ! -s "$output_file" ]; then
    echo "scenario,request_id,status_code,elapsed_sec,bytes" > "$output_file"
  fi
}

run_benchmark() {
  local scenario="$1"
  local url="$2"
  local token="$3"
  local header="$4"
  local use_mtls="$5"
  local output_file="$6"
  append_csv_header "$output_file"

  local total concurrency in_flight=0
  total="$(positive_int "$REQUESTS" 200)"
  concurrency="$(positive_int "$CONCURRENCY" 1)"
  local i=0
  local cert=""
  local key=""
  if [ "$use_mtls" = "1" ]; then
    cert="$CLIENT_CERT"
    key="$CLIENT_KEY"
  fi

  for ((i = 1; i <= total; i++)); do
    request_json "$scenario" "$i" "$url" "$cert" "$key" "$token" "$header" "$output_file" &
    in_flight=$((in_flight + 1))
    if ((in_flight >= concurrency)); then
      wait -n
      in_flight=$((in_flight - 1))
    fi
  done

  if ((in_flight > 0)); then
    wait
  fi
}

summarize_csv() {
  local file="$1"
  awk -F, '
    NR == 1 { next }
    {
      status=$3 + 0
      duration=$4 + 0
      total++
      elapsed += duration
      if ($3 == 200) ok++
      if ($3 == 403) reject_403++
      if (NR == 2 || duration < min) min=duration
      if (NR == 2 || duration > max) max=duration
    }
    END {
      if (total > 0) {
        avg = elapsed / total
        throughput = (total / (elapsed > 0 ? elapsed : 1))
        reject_ratio = (total > 0) ? ((reject_403 / total) * 100.0) : 0
        printf("requests=%d ok=%d fail=%d avg_sec=%.4f min_sec=%.4f max_sec=%.4f approx_rps=%.2f reject_403=%d reject_403_ratio=%.2f%%\n", total, ok, total-ok, avg, min, max, throughput, reject_403, reject_ratio)
      } else {
        print "requests=0"
      }
    }' "$file"
}

append_summary_csv_row() {
  local source_file="$1"
  local scenario="$2"
  local output_file="$3"

  awk -F, -v scenario="$scenario" '
    NR == 1 { next }
    {
      status=$3 + 0
      duration=$4 + 0
      total++
      elapsed += duration
      if ($3 == 200) ok++
      if ($3 == 403) reject_403++
      if (NR == 2 || duration < min) min=duration
      if (NR == 2 || duration > max) max=duration
      status_counts[status]++
    }
    END {
      if (total > 0) {
        avg = elapsed / total
        throughput = (total / (elapsed > 0 ? elapsed : 1))
        fail = total - ok
        reject_ratio = (total > 0) ? ((reject_403 / total) * 100.0) : 0
        printf("%s,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d\n", scenario, total, ok, fail, avg, min, max, throughput, reject_403, reject_ratio)
        exit
      }
      printf("%s,0,0,0,0,0,0,0,0,0\n", scenario)
    }' "$source_file" >> "$output_file"
}

print_summary_banner() {
  local file="$1"
  echo "--------------------------------------"
  echo "Benchmark summary:"
  summarize_csv "$file"
  echo "--------------------------------------"
}
