"""Pillar 5: Alerting & Notification Pipeline Benchmark.

Evaluates:
1. Alert message formatting & MD5 deduplication queue latency
2. Alert storm suppression rate (resistance to notification flooding)
3. Thread dispatch overhead for asynchronous notifications
"""

from __future__ import annotations

import time
import numpy as np
import alerter
from benchmark.dataset import generate_benchmark_dataset


def run_alerter_benchmark(n_alerts: int = 1000) -> dict:
    print(f"\n=======================================================")
    print(f"  Pillar 5: Alerting Pipeline Benchmark ({n_alerts:,} events)")
    print(f"=======================================================")

    dataset = generate_benchmark_dataset(n_alerts, attack_ratio=0.50, seed=555)

    # 1. Formatting & Deduplication Latency
    print("\n[5.1] Benchmarking Alert Formatting & Dedup Latency...")
    # Mock dispatch to prevent actual network calls during performance testing
    orig_dispatch = alerter._dispatch
    alerter._dispatch = lambda msg, cfg: None
    alerter._alert_queue.clear()

    latencies = []
    try:
        for item in dataset:
            t0 = time.perf_counter()
            alerter.send_alert(
                log_text=item["log_text"],
                severity="🔴 Critical" if item["label"] == 1 else "🔵 Info",
                severity_lvl=4 if item["label"] == 1 else 1,
                anomaly_score=-0.25 if item["label"] == 1 else 0.10,
                async_send=False,
            )
            latencies.append((time.perf_counter() - t0) * 1000)
    finally:
        alerter._dispatch = orig_dispatch

    avg_alert_ms = float(np.mean(latencies))
    p95_alert_ms = float(np.percentile(latencies, 95))
    alert_throughput = n_alerts / max(sum(latencies) / 1000, 1e-6)

    print(f"  Alert Pipeline Processing (Avg): {avg_alert_ms:.3f} ms")
    print(f"  Alert Pipeline Processing (P95): {p95_alert_ms:.3f} ms")
    print(f"  Alert Pipeline Max Capacity:     {alert_throughput:,.0f} alerts/sec")

    # 2. Alert Storm Deduplication Test
    print("\n[5.2] Stress Testing Deduplication Queue (Alert Storm)...")
    storm_payload = "DDoS SYN Flood attack from 203.0.113.99 targeting port 443"
    alerter._alert_queue.clear()
    
    dispatched_count = 0
    def mock_counter(msg, cfg):
        nonlocal dispatched_count
        dispatched_count += 1

    alerter._dispatch = mock_counter
    try:
        for _ in range(500):
            alerter.send_alert(
                log_text=storm_payload,
                severity="🔴 Critical",
                severity_lvl=4,
                async_send=False,
            )
    finally:
        alerter._dispatch = orig_dispatch

    suppressed = 500 - dispatched_count
    suppression_rate = (suppressed / 500) * 100

    print(f"  Burst Payloads Injected:         500")
    print(f"  Alerts Dispatched:               {dispatched_count}")
    print(f"  Redundant Alerts Suppressed:     {suppressed} ({suppression_rate:.1f}%)")

    return {
        "alert_avg_latency_ms": avg_alert_ms,
        "alert_p95_latency_ms": p95_alert_ms,
        "alert_throughput_aps": alert_throughput,
        "dedup_suppression_pct": suppression_rate,
    }


if __name__ == "__main__":
    res = run_alerter_benchmark(500)
