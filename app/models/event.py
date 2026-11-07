"""Normalized SecureLog event model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Event:
    timestamp: str = field(default_factory=_utc_now_iso)
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str = "unknown"
    src_port: int | None = None
    dst_port: int | None = None
    packet_size: int | None = None
    tcp_flags: str | None = None
    dns_query: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    traffic_direction: str | None = None
    packet_metadata: dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    event_type: str = "network_event"
    raw_evidence_ref: str | None = None
    confidence_score: float = 0.0
    raw_payload: str | None = None
    event_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "tcp_flags": self.tcp_flags,
            "dns_query": self.dns_query,
            "http_method": self.http_method,
            "http_host": self.http_host,
            "http_uri": self.http_uri,
            "traffic_direction": self.traffic_direction,
            "packet_metadata": self.packet_metadata,
            "severity": self.severity,
            "event_type": self.event_type,
            "raw_evidence_ref": self.raw_evidence_ref,
            "confidence_score": self.confidence_score,
            "raw_payload": self.raw_payload,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        return cls(
            event_id=data.get("event_id"),
            timestamp=data.get("timestamp", _utc_now_iso()),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            protocol=data.get("protocol", "unknown"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            packet_size=data.get("packet_size"),
            tcp_flags=data.get("tcp_flags"),
            dns_query=data.get("dns_query"),
            http_method=data.get("http_method"),
            http_host=data.get("http_host"),
            http_uri=data.get("http_uri"),
            traffic_direction=data.get("traffic_direction"),
            packet_metadata=dict(data.get("packet_metadata") or {}),
            severity=data.get("severity", "info"),
            event_type=data.get("event_type", "network_event"),
            raw_evidence_ref=data.get("raw_evidence_ref"),
            confidence_score=float(data.get("confidence_score") or 0.0),
            raw_payload=data.get("raw_payload"),
        )
