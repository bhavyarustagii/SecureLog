"""Master Benchmark Orchestrator for SecureLog.

Executes all 5 benchmark pillars:
- Pillar 1: ML Model Detection Efficacy (Isolation Forest, Random Forest, SVM, Autoencoder)
- Pillar 2: Network Traffic Ingestion & Signature Matching Throughput
- Pillar 3: SQLite Persistence & Transaction Throughput
- Pillar 4: Blockchain Forensic Ledger & EVM Gas Analysis
- Pillar 5: Alerting Pipeline & Deduplication Efficiency

Outputs:
- Live console summary tables
- JSON benchmark dump: benchmark/benchmark_results.json
"""

from __future__ import annotations

import os
import sys
import json
import time

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.bench_ml import run_ml_benchmark
from benchmark.bench_network import run_network_benchmark
from benchmark.bench_storage import run_storage_benchmark
from benchmark.bench_blockchain import run_blockchain_benchmark
from benchmark.bench_alerter import run_alerter_benchmark


def main():
    print("=" * 70)
    print("   SecureLog – Automated Benchmark Suite")
    print("   AI-Powered Security Monitoring Platform")
    print("=" * 70)
    start_time = time.time()

    ml_results = run_ml_benchmark(n_train=2500, n_test=1200)
    net_results = run_network_benchmark(n_packets=3000)
    storage_results = run_storage_benchmark(n_events=1200)
    bc_results = run_blockchain_benchmark(n_logs=1000)
    alert_results = run_alerter_benchmark(n_alerts=800)

    total_time = time.time() - start_time

    # Consolidate into full report structure
    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_benchmark_duration_s": round(total_time, 2),
        "pillar_1_ml_models": ml_results,
        "pillar_2_network": net_results,
        "pillar_3_storage": storage_results,
        "pillar_4_blockchain": bc_results,
        "pillar_5_alerting": alert_results,
    }

    results_file = os.path.join(PROJECT_ROOT, "benchmark", "benchmark_results.json")
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 70)
    print("                      BENCHMARK COMPLETE")
    print("=" * 70)
    print(f"Results saved to: {results_file}")
    print(f"Total Suite Execution Time: {total_time:.2f} seconds\n")


if __name__ == "__main__":
    main()
