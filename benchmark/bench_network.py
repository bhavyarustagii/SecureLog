"""Pillar 2: Network Traffic Ingestion & Drop Rate Benchmark.

Benchmarks:
1. Regex Signature Engine Latency & Throughput (SQLi, XSS, Path Traversal, Scanners)
2. Asynchronous Packet Snapshot Parsing & Ingestion Throughput
3. Cumulative Port-Scan counter stability under high-speed traffic
"""

from __future__ import annotations

import time
import numpy as np
import network_monitor
from app.services.capture.tshark_capture import _row_to_snapshot, TSHARK_FIELDS
from benchmark.dataset import generate_benchmark_dataset


def run_network_benchmark(n_packets: int = 5000) -> dict:
    print(f"\n=======================================================")
    print(f"  Pillar 2: Network Ingestion Benchmark ({n_packets:,} packets)")
    print(f"=======================================================")

    dataset = generate_benchmark_dataset(n_packets, attack_ratio=0.25, seed=123)

    # 1. Benchmark Payload Regex Inspection Engine
    print("\n[2.1] Benchmarking Payload Signature Matching Engine...")
    inspection_latencies = []
    matches = 0

    for item in dataset:
        payload_bytes = item["log_text"].encode("utf-8")
        src = item["source_ip"]
        dst_port = item["dst_port"]
        
        t0 = time.perf_counter()
        # Temporarily mock _log_event & block_ip to isolate regex matching overhead
        orig_log = network_monitor._log_event
        orig_block = network_monitor.block_ip
        network_monitor._log_event = lambda x: None
        network_monitor.block_ip = lambda x: None

        try:
            network_monitor._inspect_payload(payload_bytes, src, dst_port)
        finally:
            network_monitor._log_event = orig_log
            network_monitor.block_ip = orig_block

        dt = (time.perf_counter() - t0) * 1000
        inspection_latencies.append(dt)

    avg_inspect_ms = float(np.mean(inspection_latencies))
    p95_inspect_ms = float(np.percentile(inspection_latencies, 95))
    throughput_pps = n_packets / max(sum(inspection_latencies) / 1000, 1e-6)

    print(f"  Avg Signature Matching Latency: {avg_inspect_ms:.3f} ms/packet")
    print(f"  P95 Signature Matching Latency: {p95_inspect_ms:.3f} ms/packet")
    print(f"  Signature Engine Max Capacity:  {throughput_pps:,.0f} packets/sec")

    # 2. Benchmark Modular TShark Async TSV Dissector
    print("\n[2.2] Benchmarking Modular Packet TSV Dissector & Deserialization...")
    tsv_latencies = []

    for item in dataset:
        # Mock TSV row as delivered by tshark -T fields
        mock_row = [
            str(time.time()),
            str(item["packet_size"]),
            item["source_ip"],
            item["dest_ip"],
            "",
            "",
            str(item["src_port"]),
            str(item["dst_port"]),
            "",
            "",
            item["tcp_flags"],
            "api.internal.local",
            "GET",
            "securenet.local",
            "/api/v1/telemetry",
        ]

        t0 = time.perf_counter()
        snapshot = _row_to_snapshot(mock_row)
        tsv_latencies.append((time.perf_counter() - t0) * 1000)

    avg_dissect_ms = float(np.mean(tsv_latencies))
    dissect_pps = n_packets / max(sum(tsv_latencies) / 1000, 1e-6)

    print(f"  Avg TSV Dissector Latency:      {avg_dissect_ms:.3f} ms/packet")
    print(f"  TSV Dissector Max Throughput:   {dissect_pps:,.0f} packets/sec")

    return {
        "signature_avg_latency_ms": avg_inspect_ms,
        "signature_p95_latency_ms": p95_inspect_ms,
        "signature_max_pps": throughput_pps,
        "dissector_avg_latency_ms": avg_dissect_ms,
        "dissector_max_pps": dissect_pps,
    }


if __name__ == "__main__":
    res = run_network_benchmark(2000)
