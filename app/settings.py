"""Application settings for SecureLog.

Environment-driven configuration with safe defaults. No secrets are stored
in source files; all sensitive values must be provided via environment
variables at runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _str_env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str
    environment: str
    debug: bool

    base_dir: Path
    data_dir: Path
    db_path: Path
    log_path: Path
    evidence_dir: Path

    capture_interface: str
    capture_backend: str
    capture_enabled: bool

    websocket_enabled: bool
    websocket_path: str

    blockchain_enabled: bool
    ganache_url: str
    contract_address: str

    log_level: str
    sqlite_busy_timeout_ms: int
    event_retention_days: int

    @property
    def sqlite_url(self) -> str:
        return f"sqlite:///{self.db_path.as_posix()}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    base_dir = Path(__file__).resolve().parents[1]
    data_dir = Path(_str_env("SECURELOG_DATA_DIR", str(base_dir / "data")))
    data_dir.mkdir(parents=True, exist_ok=True)

    evidence_dir = Path(_str_env("SECURELOG_EVIDENCE_DIR", str(data_dir / "evidence")))
    evidence_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        app_name=_str_env("SECURELOG_APP_NAME", "SecureLog"),
        environment=_str_env("SECURELOG_ENV", "development"),
        debug=_bool_env("SECURELOG_DEBUG", False),
        base_dir=base_dir,
        data_dir=data_dir,
        db_path=Path(_str_env("SECURELOG_DB_PATH", str(data_dir / "securelog.db"))),
        log_path=Path(_str_env("SECURELOG_LOG_PATH", str(data_dir / "securelog.jsonl"))),
        evidence_dir=evidence_dir,
        capture_interface=_str_env("CAPTURE_INTERFACE", "Wi-Fi"),
        capture_backend=_str_env("SECURELOG_CAPTURE_BACKEND", "pyshark"),
        capture_enabled=_bool_env("SECURELOG_CAPTURE_ENABLED", True),
        websocket_enabled=_bool_env("SECURELOG_WEBSOCKET_ENABLED", True),
        websocket_path=_str_env("SECURELOG_WEBSOCKET_PATH", "/ws/events"),
        blockchain_enabled=_bool_env("SECURELOG_BLOCKCHAIN_ENABLED", True),
        ganache_url=_str_env("GANACHE_URL", "http://127.0.0.1:7545"),
        contract_address=_str_env("SECURELOG_CONTRACT_ADDRESS", ""),
        log_level=_str_env("SECURELOG_LOG_LEVEL", "INFO").upper(),
        sqlite_busy_timeout_ms=_int_env("SECURELOG_SQLITE_BUSY_TIMEOUT_MS", 5000),
        event_retention_days=_int_env("SECURELOG_EVENT_RETENTION_DAYS", 30),
    )
