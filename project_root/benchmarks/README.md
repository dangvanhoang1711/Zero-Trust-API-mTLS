# Benchmarking

This folder contains load/performance artifacts for Phase 6.3.

## Scripts

- `benchmarks/scripts/run-load-benchmarks.sh`
  - Runs the three benchmark scenarios defined by Timeline:
    - baseline request with bearer token
    - mTLS-only
    - mTLS + PoP
  - Writes result CSVs into `benchmarks/results/`.
- `benchmarks/scripts/bench-baseline-tls-bearer.sh`
  - Baseline-style scenario.
  - Note: current gateway always requires client certs, so this script documents/collects the constrained result under this topology.
- `benchmarks/scripts/bench-mtls-only.sh`
  - mTLS request with intentionally invalid token.
- `benchmarks/scripts/bench-mtls-pop.sh`
  - mTLS request with real `demo-client` token.
- `benchmarks/scripts/collect-resource-usage.sh`
  - Captures container-level resource counters from Docker.
- `benchmarks/plots/plot-benchmarks.py`
  - Generates simple latency and status-distribution charts from CSV output.

## Running

From repository root:

```bash
cd project_root/benchmarks
REQUESTS=200 SAMPLE_INTERVAL=1 INCLUDE_RESOURCE_SAMPLING=1 ./scripts/run-load-benchmarks.sh
```

## Output

- `benchmarks/results/baseline-latency.csv`
- `benchmarks/results/mtls-only-latency.csv`
- `benchmarks/results/mtls-pop-latency.csv`
- `benchmarks/results/*-resource.csv`
- `benchmarks/results/benchmark-summary.csv`

Each latency CSV contains:

```text
scenario,request_id,status_code,elapsed_sec,bytes
```

Use any preferred plotting tool (Python/Excel/Sheets) to derive p50/p95/p99 and request/second.

`benchmark-summary.csv` contains one row per scenario with:
- latency/throughput summary
- success and failure counts
- 403 reject ratio (proxy indicator for replay-heavy replay checks)
