import sqlite3
import hashlib
import re
import os
from datetime import datetime

if os.path.isdir("/data"):
    DB_PATH = "/data/securelog.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "securelog.db")

IP_REGEX = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

SEVERITY_RULES = {
    "ransomware":           ("🔴 Critical", 4),
    "malware":              ("🔴 Critical", 4),
    "ddos":                 ("🔴 Critical", 4),
    "brute-force":          ("🟠 High",     3),
    "brute force":          ("🟠 High",     3),
    "privilege escalation": ("🟠 High",     3),
    "sql injection":        ("🟠 High",     3),
    "xss":                  ("🟠 High",     3),
    "path traversal":       ("🟠 High",     3),
    "unauthorized access":  ("🟠 High",     3),
    "port scan":            ("🟡 Warning",  2),
    "ssh":                  ("🟡 Warning",  2),
    "firewall blocked":     ("🟡 Warning",  2),
    "failed login":         ("🟡 Warning",  2),
    "certificate mismatch": ("🟡 Warning",  2),
    "suspicious outbound":  ("🟡 Warning",  2),
}


def _classify(log_text: str):
    lower = log_text.lower()
    for keyword, (label, lvl) in SEVERITY_RULES.items():
        if keyword in lower:
            return label, lvl
    return "🔵 Info", 1


def _extract_ip(log_text: str):
    m = IP_REGEX.search(log_text)
    return m.group(0) if m else None


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      TEXT    NOT NULL,
                log_text       TEXT    NOT NULL,
                severity       TEXT    NOT NULL,
                severity_lvl   INTEGER NOT NULL,
                source_ip      TEXT,
                sha256_hash    TEXT    NOT NULL,
                on_chain       INTEGER NOT NULL DEFAULT 0,
                anomaly_score  REAL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_severity_lvl ON events(severity_lvl)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)
        """)
        conn.commit()
    print(f"[DB] Initialized -> {DB_PATH}")


def insert_event(log_text: str, on_chain: bool = False, anomaly_score: float = None) -> int:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity, severity_lvl = _classify(log_text)
    source_ip = _extract_ip(log_text)
    sha256 = hashlib.sha256(log_text.encode()).hexdigest()

    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO events
               (timestamp, log_text, severity, severity_lvl, source_ip, sha256_hash, on_chain, anomaly_score)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, log_text, severity, severity_lvl,
             source_ip, sha256, int(on_chain), anomaly_score)
        )
        conn.commit()
        return cur.lastrowid


def mark_on_chain(row_id: int):
    with get_connection() as conn:
        conn.execute("UPDATE events SET on_chain = 1 WHERE id = ?", (row_id,))
        conn.commit()


def update_anomaly_score(row_id: int, score: float):
    with get_connection() as conn:
        conn.execute("UPDATE events SET anomaly_score = ? WHERE id = ?", (score, row_id))
        conn.commit()


def fetch_events(limit: int = 200, min_severity: int = 1) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM events
               WHERE severity_lvl >= ?
               ORDER BY id DESC
               LIMIT ?""",
            (min_severity, limit)
        ).fetchall()
    return [dict(r) for r in rows]


def fetch_stats() -> dict:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
        ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}


def get_total_count() -> int:
    with get_connection() as conn:
        r = conn.execute("SELECT COUNT(*) as n FROM events").fetchone()
    return r["n"]


def migrate_from_txt(txt_path: str = "security_logs.txt"):
    if not os.path.exists(txt_path):
        print(f"[DB] No {txt_path} found – skipping migration.")
        return

    with get_connection() as conn:
        existing_hashes = {r[0] for r in conn.execute("SELECT sha256_hash FROM events").fetchall()}

    imported = 0
    with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            sha = hashlib.sha256(line.encode()).hexdigest()
            if sha in existing_hashes:
                continue
            insert_event(line, on_chain=False)
            imported += 1

    print(f"[DB] Migrated {imported} entries from {txt_path}")


if __name__ == "__main__":
    init_db()
    migrate_from_txt()
    rid = insert_event("TEST: SQL injection attempt from 10.0.0.1", on_chain=False)
    print(f"[DB] Test row inserted -> id={rid}")
    events = fetch_events(limit=5)
    print(f"[DB] Latest {len(events)} events:")
    for e in events:
        print(f"  [{e['timestamp']}] {e['severity']} | {e['log_text'][:60]}")
    print(f"[DB] Total events: {get_total_count()}")
    stats = fetch_stats()
    print(f"[DB] Stats: {stats}")
