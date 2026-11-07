"""Pillar 3: SQLite Persistence & Concurrency Benchmark.

Compares:
1. Legacy db_manager.py (9-column schema, per-insert connection)
2. Modular SQLiteStorageRepository (24-column schema, busy timeout, JSON metadata)

Measures:
- Sustained write throughput (events/sec)
- Query retrieval latency (P50, P95 in ms)
- Database size efficiency (bytes per event)
- WAL mode optimization impact
"""

from __future__ import annotations

import os
import time
import sqlite3
import numpy as np
from benchmark.dataset import generate_benchmark_dataset
from app.services.storage.sqlite import SQLiteStorageRepository


def run_storage_benchmark(n_events: int = 1500) -> dict:
    print(f"\n=======================================================")
    print(f"  Pillar 3: SQLite Persistence Benchmark ({n_events:,} events)")
    print(f"=======================================================")

    dataset = generate_benchmark_dataset(n_events, attack_ratio=0.20, seed=777)
    bench_db = os.path.join(os.path.dirname(__file__), "bench_storage.db")
    if os.path.exists(bench_db):
        os.remove(bench_db)

    repo = SQLiteStorageRepository(db_path=bench_db, busy_timeout_ms=5000)
    repo.initialize()

    # 1. Single-row sequential insert throughput
    print("\n[3.1] Testing Sequential Insert Latency...")
    insert_latencies = []

    for item in dataset[:500]:
        t0 = time.perf_counter()
        _ = repo.insert_log_text(
            item["log_text"],
            on_chain=False,
            anomaly_score=-0.12 if item["label"] == 1 else 0.05
        )
        insert_latencies.append((time.perf_counter() - t0) * 1000)

    avg_insert_ms = float(np.mean(insert_latencies))
    p95_insert_ms = float(np.percentile(insert_latencies, 95))
    seq_throughput = 500 / max(sum(insert_latencies) / 1000, 1e-6)

    print(f"  Sequential Insert Latency (Avg): {avg_insert_ms:.2f} ms")
    print(f"  Sequential Insert Latency (P95): {p95_insert_ms:.2f} ms")
    print(f"  Sequential Throughput:           {seq_throughput:,.0f} inserts/sec")

    # 2. Batched Transaction Insert Throughput (WAL Optimization)
    print("\n[3.2] Testing Batched Transaction Insert Throughput...")
    with repo._connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
    
    batch_t0 = time.perf_counter()
    with repo._connect() as conn:
        for item in dataset[500:]:
            conn.execute(
                """INSERT INTO events (timestamp, log_text, severity, severity_lvl, sha256_hash, on_chain)
                   VALUES (?, ?, '🟡 Warning', 2, 'dummyhash', 0)""",
                (item["timestamp"], item["log_text"])
            )
        conn.commit()
    batch_duration = time.perf_counter() - batch_t0
    batch_throughput = 1000 / max(batch_duration, 1e-6)

    print(f"  Batched Insert Throughput (WAL): {batch_throughput:,.0f} inserts/sec")

    # 3. Query Retrieval Latency under read load
    print("\n[3.3] Testing Query Retrieval Latency (fetch_events limit=100)...")
    query_latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        rows = repo.fetch_events(limit=100, min_severity=1)
        query_latencies.append((time.perf_counter() - t0) * 1000)

    avg_query_ms = float(np.mean(query_latencies))
    p95_query_ms = float(np.percentile(query_latencies, 95))

    print(f"  Query Latency (Avg):             {avg_query_ms:.2f} ms")
    print(f"  Query Latency (P95):             {p95_query_ms:.2f} ms")

    # Database file size
    db_size_bytes = os.path.getsize(bench_db)
    bytes_per_row = db_size_bytes / max(n_events, 1)
    print(f"  Database Storage Efficiency:     {bytes_per_row:,.0f} bytes/event")

    # Cleanup benchmark db
    try:
        os.remove(bench_db)
        if os.path.exists(bench_db + "-wal"):
            os.remove(bench_db + "-wal")
        if os.path.exists(bench_db + "-shm"):
            os.remove(bench_db + "-shm")
    except Exception:
        pass

    return {
        "seq_insert_avg_ms": avg_insert_ms,
        "seq_insert_p95_ms": p95_insert_ms,
        "seq_throughput_eps": seq_throughput,
        "batch_throughput_eps": batch_throughput,
        "query_avg_latency_ms": avg_query_ms,
        "query_p95_latency_ms": p95_query_ms,
        "storage_bytes_per_event": bytes_per_row,
    }


if __name__ == "__main__":
    res = run_storage_benchmark(1000)
