"""Stdlib event schema for SecureLog."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class EventBaseSchema:
    timestamp: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str = "unknown"
    src_port: int | None = None
    dst_port: int | None = None
    packet_metadata: dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    event_type: str = "network_event"
    raw_evidence_ref: str | None = None
    confidence_score: float = 0.0
    raw_payload: str | None = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = _utc_now_iso()


@dataclass(slots=True)
class EventCreateSchema(EventBaseSchema):
    pass


@dataclass(slots=True)
class EventReadSchema(EventBaseSchema):
    event_id: int = 0


@dataclass(slots=True)
class EventListSchema:
    items: list[EventReadSchema] = field(default_factory=list)
    total: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"items": [asdict(item) for item in self.items], "total": self.total}
