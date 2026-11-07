"""Storage repository abstractions for SecureLog."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from app.models.event import Event


class StorageRepository(ABC):
    """Database-agnostic repository contract."""

    @abstractmethod
    def initialize(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def insert_event(self, event: Event) -> int:
        raise NotImplementedError

    @abstractmethod
    def insert_log_text(self, log_text: str, on_chain: bool = False, anomaly_score: float | None = None) -> int:
        raise NotImplementedError

    @abstractmethod
    def mark_on_chain(self, row_id: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def update_anomaly_score(self, row_id: int, score: float) -> None:
        raise NotImplementedError

    @abstractmethod
    def fetch_events(self, limit: int = 200, min_severity: int = 1) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def fetch_stats(self) -> dict[str, int]:
        raise NotImplementedError

    @abstractmethod
    def get_total_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def migrate_from_txt(self, txt_path: str | Path) -> int:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError
