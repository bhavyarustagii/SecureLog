"""SecureLog backend bootstrap.

Framework-agnostic application wiring for the modular backend.
This module starts live tshark ingestion when capture is enabled.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from app.core.logging import configure_logging, get_logger
from app.models.event import Event
from app.settings import Settings, get_settings
from app.services.capture.ingestor import LivePacketIngestor
from app.services.storage.repository import StorageRepository
from app.services.storage.sqlite import SQLiteStorageRepository


@dataclass(slots=True)
class SecureLogApplication:
    settings: Settings
    repository: StorageRepository

    def initialize(self) -> None:
        configure_logging()
        self.repository.initialize()

    def ingest_log_text(self, log_text: str, on_chain: bool = False, anomaly_score: float | None = None) -> int:
        return self.repository.insert_log_text(log_text, on_chain=on_chain, anomaly_score=anomaly_score)

    def store_event(self, event: Event) -> int:
        return self.repository.insert_event(event)

    def fetch_events(self, limit: int = 200, min_severity: int = 1) -> list[dict[str, Any]]:
        return self.repository.fetch_events(limit=limit, min_severity=min_severity)

    def fetch_stats(self) -> dict[str, int]:
        return self.repository.fetch_stats()

    def total_events(self) -> int:
        return self.repository.get_total_count()


def create_repository(settings: Settings | None = None) -> StorageRepository:
    config = settings or get_settings()
    return SQLiteStorageRepository(
        db_path=config.db_path,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )


def create_application(settings: Settings | None = None) -> SecureLogApplication:
    config = settings or get_settings()
    repository = create_repository(config)
    return SecureLogApplication(settings=config, repository=repository)


def create_ingestor(
    settings: Settings | None = None,
    repository: StorageRepository | None = None,
) -> LivePacketIngestor:
    config = settings or get_settings()
    store = repository or create_repository(config)
    return LivePacketIngestor(
        repository=store,
        interface=config.capture_interface,
        tshark_path=None,
        capture_filter=None,
    )


def normalize_legacy_log(log_text: str) -> Event:
    return Event(
        protocol="unknown",
        severity="info",
        event_type="log_event",
        confidence_score=0.0,
        raw_payload=log_text,
    )


async def run_live_capture(app: SecureLogApplication) -> None:
    logger = get_logger(__name__)
    ingestor = create_ingestor(app.settings, app.repository)

    logger.info(
        "SecureLog live capture configured",
        extra={
            "event_type": "capture_configured",
            "source": "app.main",
            "protocol": "tshark",
            "src_ip": None,
            "dst_ip": None,
        },
    )
    await ingestor.run_forever()


def main() -> int:
    app = create_application()
    app.initialize()

    logger = get_logger(__name__)
    logger.info(
        "SecureLog backend initialized",
        extra={
            "event_type": "backend_startup",
            "source": "app.main",
        },
    )

    if not app.settings.capture_enabled:
        logger.info(
            "Live capture disabled by configuration",
            extra={
                "event_type": "capture_disabled",
                "source": "app.main",
                "protocol": app.settings.capture_backend,
            },
        )
        return 0

    try:
        asyncio.run(run_live_capture(app))
    except KeyboardInterrupt:
        logger.info(
            "SecureLog live capture stopped",
            extra={
                "event_type": "capture_stop",
                "source": "app.main",
                "protocol": "tshark",
            },
        )
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
