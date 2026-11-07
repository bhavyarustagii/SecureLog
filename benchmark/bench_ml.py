"""Pillar 1: Machine Learning Detection Efficacy Benchmark.

Evaluates:
- Existing Isolation Forest
- Calibrated / Scaled Isolation Forest
- Random Forest Classifier (Supervised)
- One-Class SVM (Unsupervised)
- SVM Classifier (Supervised)
- Neural Autoencoder (Reconstruction Error)

Calculates:
- Detection Rate / Recall
- Precision
- F1-Score
- False Positive Rate (FPR)
- ROC-AUC
- Single-sample inference latency (ms)
- Batch inference throughput (samples/sec)
- Model training duration (s)
"""

from __future__ import annotations

import time
import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from benchmark.dataset import generate_benchmark_dataset
from benchmark.models import (
    ExistingIsolationForestModel,
    RetrainedIsolationForestModel,
    RandomForestModel,
    SVMModel,
    NeuralAutoencoderModel,
)


def run_ml_benchmark(n_train: int = 3000, n_test: int = 1500, seed: int = 42) -> list[dict]:
    print(f"\n=======================================================")
    print(f"  Pillar 1: ML Detection Benchmark (Train={n_train}, Test={n_test})")
    print(f"=======================================================")

    # Generate train and test datasets with strict isolation
    train_data = generate_benchmark_dataset(n_train, attack_ratio=0.15, seed=seed)
    test_data = generate_benchmark_dataset(n_test, attack_ratio=0.20, seed=seed + 1)

    y_train = np.array([d["label"] for d in train_data])
    y_test = np.array([d["label"] for d in test_data])
    
    # Train data for unsupervised baseline (mostly benign)
    benign_train = [d for d in train_data if d["label"] == 0]

    models = [
        ExistingIsolationForestModel(),
        RetrainedIsolationForestModel(contamination=0.15),
        RandomForestModel(),
        SVMModel(mode="one_class"),
        SVMModel(mode="supervised"),
        NeuralAutoencoderModel(),
    ]

    results: list[dict] = []

    for m in models:
        print(f"\nEvaluating: {m.name}...")

        # Measure Training Time
        if m.is_supervised:
            train_time = m.fit(train_data, y_train)
        else:
            if isinstance(m, ExistingIsolationForestModel):
                train_time = 0.0  # Already pre-trained from ml_model.pkl
            elif isinstance(m, RetrainedIsolationForestModel):
                train_time = m.fit(train_data)
            elif isinstance(m, SVMModel):
                train_time = m.fit(benign_train[:1500])  # OC-SVM fits on normal traffic
            elif isinstance(m, NeuralAutoencoderModel):
                train_time = m.fit(benign_train)

        # Measure Single-Sample Latency (averaged over 50 samples)
        sample_latencies = []
        for i in range(min(50, len(test_data))):
            t_start = time.perf_counter()
            _ = m.predict_scores([test_data[i]])
            sample_latencies.append((time.perf_counter() - t_start) * 1000)
        p50_latency_ms = float(np.median(sample_latencies))

        # Measure Batch Inference Throughput
        t_batch_start = time.perf_counter()
        raw_scores = m.predict_scores(test_data)
        batch_duration = time.perf_counter() - t_batch_start
        throughput_sps = len(test_data) / max(batch_duration, 1e-6)

        # Invert score direction if model outputs normality scores (Isolation Forest / OC-SVM)
        # Higher score must indicate higher probability of attack for ROC-AUC
        if isinstance(m, (ExistingIsolationForestModel, RetrainedIsolationForestModel, SVMModel)) and not m.is_supervised:
            eval_scores = -raw_scores
        else:
            eval_scores = raw_scores

        # Compute ROC-AUC
        try:
            auc = float(roc_auc_score(y_test, eval_scores))
        except Exception:
            auc = 0.50

        # Predict binary classifications
        if isinstance(m, ExistingIsolationForestModel):
            y_pred = (raw_scores < 0.0).astype(int)
        elif isinstance(m, RetrainedIsolationForestModel):
            y_pred = (raw_scores < 0.0).astype(int)
        elif isinstance(m, RandomForestModel):
            y_pred = (raw_scores >= 0.5).astype(int)
        elif isinstance(m, SVMModel):
            y_pred = (raw_scores < 0.0).astype(int) if not m.is_supervised else (raw_scores >= 0.5).astype(int)
        elif isinstance(m, NeuralAutoencoderModel):
            threshold = float(np.percentile(raw_scores, 80))
            y_pred = (raw_scores > threshold).astype(int)

        # Classification Metrics
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        
        recall = float(recall_score(y_test, y_pred, zero_division=0))
        precision = float(precision_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        fpr = float(fp / max(fp + tn, 1))

        res = {
            "model": m.name,
            "type": "Supervised" if m.is_supervised else "Unsupervised",
            "recall": recall,
            "precision": precision,
            "f1_score": f1,
            "fpr": fpr,
            "roc_auc": auc,
            "p50_latency_ms": p50_latency_ms,
            "throughput_sps": throughput_sps,
            "train_time_sec": train_time,
        }
        results.append(res)
        print(f"  Recall (Detection Rate): {recall:.2%}")
        print(f"  Precision:               {precision:.2%}")
        print(f"  F1-Score:                {f1:.4f}")
        print(f"  FPR (False Positives):   {fpr:.2%}")
        print(f"  ROC-AUC:                 {auc:.4f}")
        print(f"  Latency (P50):           {p50_latency_ms:.2f} ms")
        print(f"  Throughput:              {throughput_sps:,.0f} samples/s")

    return results


if __name__ == "__main__":
    res = run_ml_benchmark(n_train=2000, n_test=1000)
