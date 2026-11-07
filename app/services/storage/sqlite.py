"""SQLite storage backend for SecureLog."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models.event import Event
from app.services.storage.repository import StorageRepository


_SEVERITY_RULES: tuple[tuple[str, str, int], ...] = (
    ("ransomware", "🔴 Critical", 4),
    ("malware", "🔴 Critical", 4),
    ("ddos", "🔴 Critical", 4),
    ("brute-force", "🟠 High", 3),
    ("brute force", "🟠 High", 3),
    ("privilege escalation", "🟠 High", 3),
    ("sql injection", "🟠 High", 3),
    ("xss", "🟠 High", 3),
    ("path traversal", "🟠 High", 3),
    ("unauthorized access", "🟠 High", 3),
    ("port scan", "🟡 Warning", 2),
    ("ssh", "🟡 Warning", 2),
    ("firewall blocked", "🟡 Warning", 2),
    ("failed login", "🟡 Warning", 2),
    ("certificate mismatch", "🟡 Warning", 2),
    ("suspicious outbound", "🟡 Warning", 2),
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utc_now_sqlite() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _classify(log_text: str) -> tuple[str, int]:
    lower = log_text.lower()
    for keyword, label, level in _SEVERITY_RULES:
        if keyword in lower:
            return label, level
    return "🔵 Info", 1


def _extract_ip(log_text: str) -> str | None:
    import re

    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", log_text)
    return match.group(0) if match else None


def _summarize_event(event: Event) -> str:
    parts: list[str] = [f"{event.protocol.upper()} event"]
    if event.src_ip or event.dst_ip:
        src = event.src_ip or "?"
        dst = event.dst_ip or "?"
        parts.append(f"{src} → {dst}")
    if event.src_port is not None or event.dst_port is not None:
        parts.append(f"ports {event.src_port or '?'}→{event.dst_port or '?'}")
    if event.dns_query:
        parts.append(f"dns={event.dns_query}")
    if event.http_method:
        target = event.http_host or ""
        uri = event.http_uri or ""
        parts.append(f"http={event.http_method} {target}{uri}".strip())
    if event.tcp_flags:
        parts.append(f"flags={event.tcp_flags}")
    if event.packet_size is not None:
        parts.append(f"len={event.packet_size}")
    if event.traffic_direction:
        parts.append(f"dir={event.traffic_direction}")
    return " | ".join(parts)


class SQLiteStorageRepository(StorageRepository):
    def __init__(self, db_path: str | Path, busy_timeout_ms: int = 5000) -> None:
        self.db_path = Path(db_path)
        self.busy_timeout_ms = busy_timeout_ms
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        return conn

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp          TEXT    NOT NULL,
                    log_text           TEXT    NOT NULL,
                    severity           TEXT    NOT NULL,
                    severity_lvl       INTEGER NOT NULL,
                    source_ip          TEXT,
                    dest_ip            TEXT,
                    protocol           TEXT    NOT NULL DEFAULT 'unknown',
                    src_port           INTEGER,
                    dst_port           INTEGER,
                    packet_size        INTEGER,
                    tcp_flags          TEXT,
                    dns_query          TEXT,
                    http_method        TEXT,
                    http_host          TEXT,
                    http_uri           TEXT,
                    traffic_direction  TEXT,
                    packet_metadata    TEXT    NOT NULL DEFAULT '{}',
                    sha256_hash        TEXT    NOT NULL,
                    on_chain           INTEGER NOT NULL DEFAULT 0,
                    anomaly_score      REAL,
                    event_type         TEXT    NOT NULL DEFAULT 'network_event',
                    raw_evidence_ref   TEXT,
                    confidence_score   REAL    NOT NULL DEFAULT 0.0,
                    raw_payload        TEXT
                )
                """
            )
            self._ensure_column(conn, "packet_size", "INTEGER")
            self._ensure_column(conn, "tcp_flags", "TEXT")
            self._ensure_column(conn, "dns_query", "TEXT")
            self._ensure_column(conn, "http_method", "TEXT")
            self._ensure_column(conn, "http_host", "TEXT")
            self._ensure_column(conn, "http_uri", "TEXT")
            self._ensure_column(conn, "traffic_direction", "TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity_lvl ON events(severity_lvl)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
            conn.commit()

    def insert_event(self, event: Event) -> int:
        timestamp = event.timestamp or _utc_now_iso()
        summary = _summarize_event(event)
        raw_payload = event.raw_payload or json.dumps(event.to_dict(), ensure_ascii=False, default=str)
        severity = event.severity or "🔵 Info"
        severity_lvl = self._severity_level(severity)
        source_ip = event.src_ip or _extract_ip(summary) or _extract_ip(raw_payload)
        packet_metadata = dict(event.packet_metadata or {})
        packet_metadata.setdefault("raw_payload", event.raw_payload)
        packet_metadata.setdefault("packet_size", event.packet_size)
        packet_metadata.setdefault("tcp_flags", event.tcp_flags)
        packet_metadata.setdefault("dns_query", event.dns_query)
        packet_metadata.setdefault("http_method", event.http_method)
        packet_metadata.setdefault("http_host", event.http_host)
        packet_metadata.setdefault("http_uri", event.http_uri)
        packet_metadata.setdefault("traffic_direction", event.traffic_direction)
        sha256_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO events (
                    timestamp, log_text, severity, severity_lvl, source_ip, dest_ip,
                    protocol, src_port, dst_port, packet_size, tcp_flags, dns_query,
                    http_method, http_host, http_uri, traffic_direction, packet_metadata,
                    sha256_hash, on_chain, anomaly_score, event_type, raw_evidence_ref,
                    confidence_score, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    summary,
                    severity,
                    severity_lvl,
                    source_ip,
                    event.dst_ip,
                    event.protocol,
                    event.src_port,
                    event.dst_port,
                    event.packet_size,
                    event.tcp_flags,
                    event.dns_query,
                    event.http_method,
                    event.http_host,
                    event.http_uri,
                    event.traffic_direction,
                    json.dumps(packet_metadata, ensure_ascii=False, default=str),
                    sha256_hash,
                    0,
                    None,
                    event.event_type,
                    event.raw_evidence_ref,
                    float(event.confidence_score or 0.0),
                    raw_payload,
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def insert_log_text(self, log_text: str, on_chain: bool = False, anomaly_score: float | None = None) -> int:
        severity, severity_lvl = _classify(log_text)
        timestamp = _utc_now_iso()
        sha256_hash = hashlib.sha256(log_text.encode("utf-8")).hexdigest()

        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO events (
                    timestamp, log_text, severity, severity_lvl, source_ip, dest_ip,
                    protocol, src_port, dst_port, packet_size, tcp_flags, dns_query,
                    http_method, http_host, http_uri, traffic_direction, packet_metadata,
                    sha256_hash, on_chain, anomaly_score, event_type, raw_evidence_ref,
                    confidence_score, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    log_text,
                    severity,
                    severity_lvl,
                    _extract_ip(log_text),
                    None,
                    "unknown",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    "{}",
                    sha256_hash,
                    int(on_chain),
                    anomaly_score,
                    "log_event",
                    None,
                    0.0,
                    log_text,
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def mark_on_chain(self, row_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE events SET on_chain = 1 WHERE id = ?", (row_id,))
            conn.commit()

    def update_anomaly_score(self, row_id: int, score: float) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE events SET anomaly_score = ? WHERE id = ?", (score, row_id))
            conn.commit()

    def fetch_events(self, limit: int = 200, min_severity: int = 1) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE severity_lvl >= ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (min_severity, limit),
            ).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def fetch_stats(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT severity, COUNT(*) AS cnt FROM events GROUP BY severity").fetchall()
        return {str(row["severity"]): int(row["cnt"]) for row in rows}

    def get_total_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"]) if row else 0

    def migrate_from_txt(self, txt_path: str | Path) -> int:
        path = Path(txt_path)
        if not path.exists():
            return 0

        with self._connect() as conn:
            existing_hashes = {str(row[0]) for row in conn.execute("SELECT sha256_hash FROM events").fetchall()}

        imported = 0
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                log_text = line.strip()
                if not log_text:
                    continue
                sha = hashlib.sha256(log_text.encode("utf-8")).hexdigest()
                if sha in existing_hashes:
                    continue
                self.insert_log_text(log_text, on_chain=False)
                imported += 1
        return imported

    def close(self) -> None:
        return None

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, column_name: str, column_type: str) -> None:
        try:
            conn.execute(f"ALTER TABLE events ADD COLUMN {column_name} {column_type}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                return

    @staticmethod
    def _severity_level(severity: str) -> int:
        normalized = severity.lower()
        if "critical" in normalized:
            return 4
        if "high" in normalized:
            return 3
        if "warning" in normalized:
            return 2
        return 1

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        packet_metadata = row["packet_metadata"]
        if isinstance(packet_metadata, str):
            try:
                packet_metadata = json.loads(packet_metadata)
            except json.JSONDecodeError:
                packet_metadata = {}

        return {
            "id": int(row["id"]),
            "event_id": int(row["id"]),
            "timestamp": row["timestamp"],
            "log_text": row["log_text"],
            "severity": row["severity"],
            "severity_lvl": int(row["severity_lvl"]),
            "source_ip": row["source_ip"],
            "dst_ip": row["dest_ip"],
            "protocol": row["protocol"],
            "src_port": row["src_port"],
            "dst_port": row["dst_port"],
            "packet_size": row["packet_size"],
            "tcp_flags": row["tcp_flags"],
            "dns_query": row["dns_query"],
            "http_method": row["http_method"],
            "http_host": row["http_host"],
            "http_uri": row["http_uri"],
            "traffic_direction": row["traffic_direction"],
            "packet_metadata": packet_metadata,
            "sha256_hash": row["sha256_hash"],
            "on_chain": bool(row["on_chain"]),
            "anomaly_score": row["anomaly_score"],
            "event_type": row["event_type"],
            "raw_evidence_ref": row["raw_evidence_ref"],
            "confidence_score": row["confidence_score"],
            "raw_payload": row["raw_payload"],
        }
