"""Live tshark packet streaming for SecureLog."""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Sequence


TSHARK_FIELDS: tuple[str, ...] = (
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags.str",
    "dns.qry.name",
    "http.request.method",
    "http.host",
    "http.request.uri",
)


@dataclass(slots=True)
class PacketSnapshot:
    timestamp: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_size: int | None
    tcp_flags: str | None
    dns_query: str | None
    http_method: str | None
    http_host: str | None
    http_uri: str | None
    traffic_direction: str
    raw_fields: dict[str, str] = field(default_factory=dict)


class TsharkCaptureError(RuntimeError):
    """Raised when tshark cannot be started or parsed."""


def resolve_tshark_path(explicit_path: str | None = None) -> str:
    candidates = [
        explicit_path,
        os.getenv("TSHARK_PATH"),
        "tshark",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        if candidate == "tshark":
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
            continue
        if os.path.exists(candidate):
            return candidate
    raise TsharkCaptureError(
        "tshark executable not found. Set TSHARK_PATH or install Wireshark/TShark."
    )


def _utc_iso_from_epoch(epoch_value: str | None) -> str:
    if not epoch_value:
        return datetime.now(timezone.utc).isoformat()
    try:
        return datetime.fromtimestamp(float(epoch_value), tz=timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def _parse_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _is_private_ip(address: str | None) -> bool:
    if not address:
        return False
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def _normalize_protocol(tcp_port: int | None, udp_port: int | None, dns_query: str | None, http_method: str | None) -> str:
    if dns_query:
        return "DNS"
    if http_method:
        return "HTTP"
    if tcp_port is not None:
        return "TCP"
    if udp_port is not None:
        return "UDP"
    return "IP"


def _infer_direction(src_ip: str | None, dst_ip: str | None) -> str:
    src_private = _is_private_ip(src_ip)
    dst_private = _is_private_ip(dst_ip)

    if src_private and not dst_private:
        return "outbound"
    if dst_private and not src_private:
        return "inbound"
    if src_private and dst_private:
        return "internal"
    return "external"


def _build_tcp_flags(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip() or None


def _row_to_snapshot(row: Sequence[str]) -> PacketSnapshot:
    values = list(row) + [""] * max(0, len(TSHARK_FIELDS) - len(row))
    raw = dict(zip(TSHARK_FIELDS, values, strict=False))

    src_ip = raw["ip.src"] or raw["ipv6.src"] or None
    dst_ip = raw["ip.dst"] or raw["ipv6.dst"] or None
    tcp_src = _parse_int(raw["tcp.srcport"])
    tcp_dst = _parse_int(raw["tcp.dstport"])
    udp_src = _parse_int(raw["udp.srcport"])
    udp_dst = _parse_int(raw["udp.dstport"])
    src_port = tcp_src if tcp_src is not None else udp_src
    dst_port = tcp_dst if tcp_dst is not None else udp_dst

    packet_size = _parse_int(raw["frame.len"])
    tcp_flags = _build_tcp_flags(raw["tcp.flags.str"])
    dns_query = raw["dns.qry.name"] or None
    http_method = raw["http.request.method"] or None
    http_host = raw["http.host"] or None
    http_uri = raw["http.request.uri"] or None

    return PacketSnapshot(
        timestamp=_utc_iso_from_epoch(raw["frame.time_epoch"]),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=_normalize_protocol(tcp_src, udp_src, dns_query, http_method),
        packet_size=packet_size,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        http_method=http_method,
        http_host=http_host,
        http_uri=http_uri,
        traffic_direction=_infer_direction(src_ip, dst_ip),
        raw_fields=raw,
    )


class TSharkLiveCapture:
    def __init__(
        self,
        interface: str,
        tshark_path: str | None = None,
        capture_filter: str | None = None,
        extra_args: Sequence[str] | None = None,
    ) -> None:
        self.interface = interface
        self.tshark_path = resolve_tshark_path(tshark_path)
        self.capture_filter = capture_filter
        self.extra_args = list(extra_args or [])

    def command(self) -> list[str]:
        args = [
            self.tshark_path,
            "-l",
            "-n",
            "-i",
            self.interface,
            "-T",
            "fields",
            "-E",
            "header=n",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
        ]
        if self.capture_filter:
            args.extend(["-f", self.capture_filter])
        for field_name in TSHARK_FIELDS:
            args.extend(["-e", field_name])
        args.extend(self.extra_args)
        return args

    async def stream(self) -> AsyncIterator[PacketSnapshot]:
        process = await asyncio.create_subprocess_exec(
            *self.command(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert process.stdout is not None
        assert process.stderr is not None

        stderr_task = asyncio.create_task(process.stderr.read())
        try:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                row = next(csv.reader([text], delimiter="\t", quotechar='"'))
                yield _row_to_snapshot(row)
        finally:
            process.terminate()
            await process.wait()
            if not stderr_task.done():
                stderr_task.cancel()
