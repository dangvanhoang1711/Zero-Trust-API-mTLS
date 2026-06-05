# Benchmark Visualization

This folder contains helper scripts for generating simple charts from raw benchmark
CSV output.

Run:

```bash
python3 benchmarks/plots/plot-benchmarks.py \
  --results-dir project_root/benchmarks/results \
  --output-dir project_root/benchmarks/plots
```

The script creates:
- `latency-over-time.png`: request latency trend per scenario
- `status-distribution.png`: HTTP status code distribution per scenario
- `throughput-summary.png`: throughput and average latency summary

Requirements:
- `python3`
- `matplotlib` (optional; script exits with guidance if missing)
