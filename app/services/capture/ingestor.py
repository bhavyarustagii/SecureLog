"""Live packet ingestion pipeline for SecureLog."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Any

from app.core.logging import get_logger
from app.models.event import Event
from app.services.capture.tshark_capture import PacketSnapshot, TSharkCaptureError, TSharkLiveCapture
from app.services.storage.repository import StorageRepository


class LivePacketIngestor:
    def __init__(
        self,
        repository: StorageRepository,
        interface: str,
        tshark_path: str | None = None,
        capture_filter: str | None = None,
    ) -> None:
        self.repository = repository
        self.capture = TSharkLiveCapture(
            interface=interface,
            tshark_path=tshark_path,
            capture_filter=capture_filter,
        )
        self.logger = get_logger(__name__)

    def snapshot_to_event(self, snapshot: PacketSnapshot) -> Event:
        metadata = dict(snapshot.raw_fields)
        metadata.update(
            {
                "packet_size": snapshot.packet_size,
                "tcp_flags": snapshot.tcp_flags,
                "dns_query": snapshot.dns_query,
                "http_method": snapshot.http_method,
                "http_host": snapshot.http_host,
                "http_uri": snapshot.http_uri,
                "traffic_direction": snapshot.traffic_direction,
            }
        )

        raw_payload = json.dumps(asdict(snapshot), ensure_ascii=False, default=str)

        return Event(
            timestamp=snapshot.timestamp,
            src_ip=snapshot.src_ip,
            dst_ip=snapshot.dst_ip,
            protocol=snapshot.protocol,
            src_port=snapshot.src_port,
            dst_port=snapshot.dst_port,
            packet_size=snapshot.packet_size,
            tcp_flags=snapshot.tcp_flags,
            dns_query=snapshot.dns_query,
            http_method=snapshot.http_method,
            http_host=snapshot.http_host,
            http_uri=snapshot.http_uri,
            traffic_direction=snapshot.traffic_direction,
            packet_metadata=metadata,
            severity="info",
            event_type="packet_event",
            raw_evidence_ref=f"tshark://{self.capture.interface}",
            confidence_score=1.0,
            raw_payload=raw_payload,
        )

    async def run(self) -> None:
        self.logger.info(
            "Live packet capture started",
            extra={
                "event_type": "capture_start",
                "source": "app.services.capture.ingestor",
                "protocol": "tshark",
            },
        )

        try:
            async for snapshot in self.capture.stream():
                event = self.snapshot_to_event(snapshot)
                event_id = self.repository.insert_event(event)
                event.event_id = event_id

                self.logger.info(
                    "Captured live packet",
                    extra={
                        "event_type": event.event_type,
                        "source": "app.services.capture.ingestor",
                        "event_id": event_id,
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        "protocol": event.protocol,
                        "src_port": event.src_port,
                        "dst_port": event.dst_port,
                        "packet_size": event.packet_size,
                        "tcp_flags": event.tcp_flags,
                        "dns_query": event.dns_query,
                        "http_method": event.http_method,
                        "http_host": event.http_host,
                        "http_uri": event.http_uri,
                        "traffic_direction": event.traffic_direction,
                    },
                )
        except TSharkCaptureError as exc:
            self.logger.error(
                "Live capture could not start",
                extra={
                    "event_type": "capture_error",
                    "source": "app.services.capture.ingestor",
                    "protocol": "tshark",
                },
                exc_info=exc,
            )
            raise
        except asyncio.CancelledError:
            self.logger.info(
                "Live packet capture cancelled",
                extra={
                    "event_type": "capture_stop",
                    "source": "app.services.capture.ingestor",
                    "protocol": "tshark",
                },
            )
            raise
        except Exception as exc:
            self.logger.exception(
                "Live packet ingestion failed",
                extra={
                    "event_type": "capture_error",
                    "source": "app.services.capture.ingestor",
                    "protocol": "tshark",
                },
            )
            raise RuntimeError("Live packet ingestion failed") from exc

    async def run_forever(self) -> None:
        while True:
            await self.run()
