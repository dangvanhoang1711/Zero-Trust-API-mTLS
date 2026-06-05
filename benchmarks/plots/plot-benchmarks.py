#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean
from typing import Dict, List, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot benchmark latency and status data.")
    parser.add_argument(
        "--results-dir",
        default="project_root/benchmarks/results",
        help="Directory containing benchmark CSV files.",
    )
    parser.add_argument(
        "--output-dir",
        default="project_root/benchmarks/plots",
        help="Directory to write PNG outputs.",
    )
    return parser.parse_args()


def ensure_matplotlib() -> None:
    try:
        import matplotlib.pyplot as plt  # type: ignore
        globals()["plt"] = plt
    except Exception as exc:
        raise SystemExit(
            "matplotlib is required to generate plots. Install with: "
            "pip install matplotlib\n"
            f"Original error: {exc}"
        )


def read_latency_csv(path: Path) -> Tuple[List[float], Counter]:
    latencies: List[float] = []
    status_counts: Counter = Counter()

    with path.open("r", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                status_counts[row["status_code"]] += 1
                latencies.append(float(row["elapsed_sec"]))
            except (KeyError, ValueError):
                continue

    return latencies, status_counts


def percentile(values: List[float], ratio: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    idx = int((ratio / 100.0) * (len(values) - 1))
    return float(values[idx])


def main() -> None:
    args = parse_args()
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ensure_matplotlib()
    plt = globals()["plt"]  # type: ignore

    scenario_data: Dict[str, List[float]] = {}
    scenario_status: Dict[str, Counter] = {}
    scenarios = sorted(results_dir.glob("*-latency.csv"))

    if not scenarios:
        print(f"No *-latency.csv files found under {results_dir}")
        return

    for path in scenarios:
        label = path.stem.replace("-latency", "")
        latencies, status_counts = read_latency_csv(path)
        scenario_data[label] = latencies
        scenario_status[label] = status_counts

    # Latency-over-time chart
    plt.figure(figsize=(10, 6))
    for label, latencies in scenario_data.items():
        plt.plot(latencies, label=label, alpha=0.8)
    plt.title("Benchmark Latency by Request")
    plt.xlabel("Request #")
    plt.ylabel("Latency (seconds)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "latency-over-time.png", dpi=150)
    plt.close()

    # Status distribution
    statuses = sorted(
        {
            status
            for counts in scenario_status.values()
            for status in counts.keys()
        }
    )
    width = 0.8 / max(1, len(scenario_data))

    plt.figure(figsize=(10, 6))
    x = range(len(statuses))
    for idx, (label, counts) in enumerate(sorted(scenario_status.items())):
        values = [counts.get(status, 0) for status in statuses]
        positions = [pos + (idx * width) for pos in x]
        plt.bar(positions, values, width=width, label=label)
    plt.title("Status Code Distribution")
    plt.xlabel("HTTP status")
    plt.ylabel("Count")
    plt.xticks([pos + (len(scenario_data) - 1) * width / 2 for pos in x], statuses)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "status-distribution.png", dpi=150)
    plt.close()

    # Throughput + avg latency summary
    labels = sorted(scenario_data.keys())
    avg_latencies = [mean(vals) if vals else 0.0 for vals in [scenario_data[k] for k in labels]]
    p95_latencies = [percentile(scenario_data[k], 95) if scenario_data[k] else 0.0 for k in labels]

    plt.figure(figsize=(10, 6))
    plt.bar([x - 0.2 for x in range(len(labels))], avg_latencies, width=0.4, label="avg")
    plt.bar([x + 0.2 for x in range(len(labels))], p95_latencies, width=0.4, label="p95")
    plt.title("Average and P95 Latency")
    plt.xlabel("Scenario")
    plt.ylabel("Latency (seconds)")
    plt.xticks(range(len(labels)), labels, rotation=20)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "throughput-summary.png", dpi=150)
    plt.close()

    print("Generated plots:")
    print("-", output_dir / "latency-over-time.png")
    print("-", output_dir / "status-distribution.png")
    print("-", output_dir / "throughput-summary.png")


if __name__ == "__main__":
    main()
