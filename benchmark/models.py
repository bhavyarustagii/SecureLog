"""Model implementations & wrappers for SecureLog Benchmarking.

Includes:
1. Existing Isolation Forest (heuristic pipeline)
2. Retrained & Scaled Isolation Forest (calibrated unsupervised baseline)
3. Supervised Random Forest Classifier
4. One-Class Support Vector Machine (OC-SVM) & Supervised Support Vector Classifier (SVC)
5. Neural Autoencoder Anomaly Detector (MLP Reconstruction Error)
"""

from __future__ import annotations

import time
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM, SVC
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

import ml_engine


class ExistingIsolationForestModel:
    """Wrapper around the existing ml_engine.py Isolation Forest implementation."""

    def __init__(self) -> None:
        self.name = "Existing Isolation Forest (Heuristic)"
        self.is_supervised = False
        # Load model once in memory to measure true algorithmic inference time
        self.model = ml_engine._load_model()
        if self.model is not None:
            self.model.n_jobs = 1

    def fit(self, events: list[dict]) -> float:
        t0 = time.perf_counter()
        ml_engine.train(events)
        self.model = ml_engine._load_model()
        if self.model is not None:
            self.model.n_jobs = 1
        return time.perf_counter() - t0

    def predict_scores(self, events: list[dict]) -> np.ndarray:
        """Returns anomaly decision scores (lower = more anomalous)."""
        if self.model is None:
            return np.zeros(len(events))
        X = ml_engine.extract_features_batch(events)
        return self.model.decision_function(X)

    def predict(self, events: list[dict], threshold: float = 0.0) -> np.ndarray:
        """Returns binary prediction (1 = Anomaly / Attack, 0 = Normal)."""
        scores = self.predict_scores(events)
        return (scores < threshold).astype(int)


class RetrainedIsolationForestModel:
    """Optimized & scaled Isolation Forest trained on realistic baseline data."""

    def __init__(self, contamination: float = 0.15) -> None:
        self.name = "Calibrated Isolation Forest (Scaled)"
        self.is_supervised = False
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=150,
            contamination=contamination,
            random_state=42,
            n_jobs=1,
        )

    def fit(self, events: list[dict]) -> float:
        t0 = time.perf_counter()
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        return time.perf_counter() - t0

    def predict_scores(self, events: list[dict]) -> np.ndarray:
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.transform(X)
        return self.model.decision_function(X_scaled)

    def predict(self, events: list[dict], threshold: float = 0.0) -> np.ndarray:
        scores = self.predict_scores(events)
        return (scores < threshold).astype(int)


class RandomForestModel:
    """Supervised Random Forest Classifier for intrusion detection."""

    def __init__(self) -> None:
        self.name = "Random Forest Classifier (Supervised)"
        self.is_supervised = True
        self.scaler = StandardScaler()
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            random_state=42,
            n_jobs=1,
        )

    def fit(self, events: list[dict], y: np.ndarray) -> float:
        t0 = time.perf_counter()
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        return time.perf_counter() - t0

    def predict_scores(self, events: list[dict]) -> np.ndarray:
        """Returns probability of attack class (1)."""
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.transform(X)
        probs = self.model.predict_proba(X_scaled)
        # return prob of attack (class 1)
        if probs.shape[1] > 1:
            return probs[:, 1]
        return probs[:, 0]

    def predict(self, events: list[dict], threshold: float = 0.5) -> np.ndarray:
        scores = self.predict_scores(events)
        return (scores >= threshold).astype(int)


class SVMModel:
    """Support Vector Machine Model (One-Class SVM & Support Vector Classifier)."""

    def __init__(self, mode: str = "one_class") -> None:
        self.mode = mode
        self.is_supervised = (mode == "supervised")
        self.name = "One-Class SVM (Unsupervised)" if mode == "one_class" else "SVM Classifier (RBF Kernel)"
        self.scaler = StandardScaler()
        if self.mode == "one_class":
            self.model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.15)
        else:
            self.model = SVC(kernel="rbf", gamma="scale", probability=True, random_state=42)

    def fit(self, events: list[dict], y: np.ndarray | None = None) -> float:
        t0 = time.perf_counter()
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.fit_transform(X)
        if self.mode == "one_class":
            self.model.fit(X_scaled)
        else:
            assert y is not None
            self.model.fit(X_scaled, y)
        return time.perf_counter() - t0

    def predict_scores(self, events: list[dict]) -> np.ndarray:
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.transform(X)
        if self.mode == "one_class":
            # decision_function: positive for inliers, negative for outliers
            return self.model.decision_function(X_scaled)
        else:
            return self.model.predict_proba(X_scaled)[:, 1]

    def predict(self, events: list[dict], threshold: float = 0.0) -> np.ndarray:
        scores = self.predict_scores(events)
        if self.mode == "one_class":
            return (scores < threshold).astype(int)
        else:
            return (scores >= 0.5).astype(int)


class NeuralAutoencoderModel:
    """Multi-Layer Neural Autoencoder measuring feature reconstruction error."""

    def __init__(self) -> None:
        self.name = "Neural Autoencoder (Reconstruction Error)"
        self.is_supervised = False
        self.scaler = StandardScaler()
        # Symmetric bottleneck architecture: 12 -> 8 -> 4 -> 8 -> 12
        self.model = MLPRegressor(
            hidden_layer_sizes=(8, 4, 8),
            activation="relu",
            max_iter=200,
            random_state=42,
            solver="adam",
            learning_rate_init=0.01,
        )

    def fit(self, events: list[dict]) -> float:
        t0 = time.perf_counter()
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.fit_transform(X)
        # Autoencoder trains to reconstruct its input: X -> X
        self.model.fit(X_scaled, X_scaled)
        return time.perf_counter() - t0

    def predict_scores(self, events: list[dict]) -> np.ndarray:
        """Returns Mean Squared Reconstruction Error per sample."""
        X = ml_engine.extract_features_batch(events)
        X_scaled = self.scaler.transform(X)
        X_recon = self.model.predict(X_scaled)
        mse = np.mean((X_scaled - X_recon) ** 2, axis=1)
        return mse

    def predict(self, events: list[dict], threshold: float | None = None) -> np.ndarray:
        scores = self.predict_scores(events)
        if threshold is None:
            threshold = float(np.percentile(scores, 85))
        return (scores > threshold).astype(int)
