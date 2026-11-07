import os
import re
import pickle
import hashlib
import numpy as np
from datetime import datetime

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml_model.pkl")
MODEL_RETRAIN_INTERVAL = 50
MIN_TRAIN_SAMPLES = 20

IP_REGEX = re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b')

SEVERITY_RULES = {
    "ransomware":           4,
    "malware":              4,
    "ddos":                 4,
    "brute-force":          3,
    "brute force":          3,
    "privilege escalation": 3,
    "sql injection":        3,
    "xss":                  3,
    "path traversal":       3,
    "unauthorized access":  3,
    "port scan":            2,
    "ssh":                  2,
    "firewall blocked":     2,
    "failed login":         2,
    "certificate mismatch": 2,
    "suspicious outbound":  2,
}


def _severity_level(log_text: str) -> int:
    lower = log_text.lower()
    for kw, lvl in SEVERITY_RULES.items():
        if kw in lower:
            return lvl
    return 1


def _last_octet(log_text: str) -> int:
    m = IP_REGEX.search(log_text)
    if m:
        try:
            return int(m.group(4))
        except ValueError:
            return 0
    return 0


def _hour_of_day(timestamp_str: str) -> int:
    try:
        return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").hour
    except Exception:
        return datetime.now().hour


def _keyword_flags(log_text: str) -> list[int]:
    lower = log_text.lower()
    return [
        int("sql" in lower or "injection" in lower),
        int("xss" in lower or "<script" in lower or "javascript:" in lower),
        int("brute" in lower or "ssh" in lower),
        int("ddos" in lower or "flood" in lower),
        int("malware" in lower or "ransomware" in lower),
        int("scan" in lower or "recon" in lower or "nmap" in lower),
        int("traversal" in lower or "../" in lower),
        int("unauthorized" in lower or "privilege" in lower),
    ]


def extract_features(log_text: str, timestamp_str: str = None) -> np.ndarray:
    if timestamp_str is None:
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    hour      = _hour_of_day(timestamp_str)
    severity  = _severity_level(log_text)
    last_oct  = _last_octet(log_text)
    text_len  = len(log_text)
    kw_flags  = _keyword_flags(log_text)

    return np.array([hour, severity, last_oct, text_len] + kw_flags, dtype=np.float32)


def extract_features_batch(events: list[dict]) -> np.ndarray:
    rows = []
    for e in events:
        rows.append(extract_features(e["log_text"], e.get("timestamp")))
    return np.vstack(rows) if rows else np.empty((0, 12))


def _save_model(model):
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)


def _load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return None


def train(events: list[dict]) -> bool:
    if len(events) < MIN_TRAIN_SAMPLES:
        print(f"[ML] Not enough data to train ({len(events)} < {MIN_TRAIN_SAMPLES}). Skipping.")
        return False

    try:
        from sklearn.ensemble import IsolationForest
        X = extract_features_batch(events)
        model = IsolationForest(
            n_estimators=150,
            contamination=0.08,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X)
        _save_model(model)
        print(f"[ML] Model trained on {len(events)} events → {MODEL_PATH}")
        return True
    except ImportError:
        print("[ML] scikit-learn not installed. Run: pip install scikit-learn")
        return False
    except Exception as e:
        print(f"[ML] Training failed: {e}")
        return False


def score(log_text: str, timestamp_str: str = None) -> float | None:
    model = _load_model()
    if model is None:
        return None
    try:
        X = extract_features(log_text, timestamp_str).reshape(1, -1)
        return float(model.decision_function(X)[0])
    except Exception as e:
        print(f"[ML] Scoring failed: {e}")
        return None


def score_batch(events: list[dict]) -> list[float | None]:
    model = _load_model()
    if model is None:
        return [None] * len(events)
    try:
        X = extract_features_batch(events)
        return [float(v) for v in model.decision_function(X)]
    except Exception as e:
        print(f"[ML] Batch scoring failed: {e}")
        return [None] * len(events)


def is_model_ready() -> bool:
    return os.path.exists(MODEL_PATH)


def auto_train_from_db():
    try:
        from db_manager import fetch_events
        events = fetch_events(limit=5000)
        if events:
            train(events)
        else:
            print("[ML] DB is empty – seeding with synthetic data for initial training.")
            _seed_train()
    except Exception as e:
        print(f"[ML] auto_train_from_db failed: {e}")


def _seed_train():
    from datetime import datetime, timedelta
    import random

    samples = [
        "Failed login attempt from 192.168.1.10",
        "Firewall blocked suspicious IP 203.0.113.45",
        "Multiple SSH failures detected from 10.0.0.5",
        "Possible port scan detected from 172.16.0.99",
        "Admin login success from 192.168.1.1",
        "Brute-force attack detected on port 22 from 198.51.100.12",
        "DDoS traffic spike from 192.0.2.77",
        "Malware signature detected in payload from 203.0.113.88",
        "Unauthorized access attempt on /admin from 10.0.0.15",
        "SQL injection attempt blocked from 198.51.100.33",
        "Suspicious outbound connection to 203.0.113.200",
        "Certificate mismatch warning for host 172.16.0.50",
        "Privilege escalation attempt detected from 192.168.1.25",
        "Ransomware pattern detected from 198.51.100.66",
        "XSS payload detected in HTTP request from 45.33.32.156",
        "Path traversal attempt: ../../etc/passwd from 198.51.100.77",
        "Normal user login from 192.168.1.100",
        "Scheduled backup completed successfully",
        "Config reload triggered by admin",
        "Routine health check passed",
    ]

    base = datetime.now()
    events = []
    for i in range(200):
        log = random.choice(samples)
        ts = (base - timedelta(minutes=random.randint(0, 10000))).strftime("%Y-%m-%d %H:%M:%S")
        events.append({"log_text": log, "timestamp": ts})

    train(events)


if __name__ == "__main__":
    print("[ML] Running self-test…")
    auto_train_from_db()

    test_logs = [
        ("Failed login attempt from 192.168.1.10",       "2026-01-01 03:15:00"),
        ("SQL injection attempt from 198.51.100.33",     "2026-01-01 02:55:00"),
        ("XSS payload detected from 45.33.32.156",       "2026-01-01 11:30:00"),
        ("DDoS traffic spike from 192.0.2.77",           "2026-01-01 14:00:00"),
        ("Admin login success from 192.168.1.1",         "2026-01-01 09:00:00"),
        ("Routine health check passed",                  "2026-01-01 12:00:00"),
    ]

    print(f"\n{'Log':<55} {'Score':>8}  Risk")
    print("-" * 75)
    for log, ts in test_logs:
        s = score(log, ts)
        risk = "⚠️ ANOMALY" if s is not None and s < 0 else "✅ Normal"
        s_str = f"{s:.4f}" if s is not None else "N/A"
        print(f"{log[:54]:<55} {s_str:>8}  {risk}")
