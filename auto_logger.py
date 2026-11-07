import os
import sys
import time
from datetime import datetime

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

for _tp in TSHARK_PATHS:
    if os.path.exists(_tp):
        os.environ["TSHARK_PATH"] = _tp
        tshark_dir = os.path.dirname(_tp)
        if tshark_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = tshark_dir + os.pathsep + os.environ.get("PATH", "")
        break

try:
    import pyshark
except ImportError:
    print("[ERROR] pyshark not installed. Run: pip install pyshark")
    sys.exit(1)

from blockchain_logger import store_log
from network_monitor import process_packet

INTERFACE = os.environ.get("CAPTURE_INTERFACE", "Wi-Fi")
PACKET_LOG_INTERVAL = 0

def format_packet(packet):
    try:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        proto = packet.highest_layer
        length = packet.length

        src_ip = dst_ip = "—"
        src_port = dst_port = ""

        if hasattr(packet, "ip"):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst

        if hasattr(packet, "tcp"):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            flags = ""
            try:
                flag_val = int(packet.tcp.flags, 16)
                flag_parts = []
                if flag_val & 0x02: flag_parts.append("SYN")
                if flag_val & 0x10: flag_parts.append("ACK")
                if flag_val & 0x01: flag_parts.append("FIN")
                if flag_val & 0x04: flag_parts.append("RST")
                if flag_val & 0x08: flag_parts.append("PSH")
                flags = f" [{','.join(flag_parts)}]" if flag_parts else ""
            except Exception:
                pass
            info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}{flags}"
        elif hasattr(packet, "udp"):
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        else:
            info = f"{src_ip} -> {dst_ip}"

        if hasattr(packet, "dns"):
            try:
                qry = packet.dns.qry_name
                info = f"DNS Query: {qry} from {src_ip}"
                proto = "DNS"
            except Exception:
                pass
        elif hasattr(packet, "http"):
            try:
                method = getattr(packet.http, "request_method", "")
                uri = getattr(packet.http, "request_uri", "")
                host = getattr(packet.http, "host", "")
                if method:
                    info = f"HTTP {method} {host}{uri} from {src_ip}"
                    proto = "HTTP"
            except Exception:
                pass
        elif hasattr(packet, "tls"):
            try:
                sni = getattr(packet.tls, "handshake_extensions_server_name", "")
                if sni:
                    info = f"TLS -> {sni} from {src_ip}"
                    proto = "TLS"
            except Exception:
                pass

        log_line = f"{proto} {info} len={length}"
        return log_line, proto
    except Exception:
        return None, None


def main():
    print(f"🔍 SecureLog Live Packet Capture")
    print(f"   Interface : {INTERFACE}")
    print(f"   Backend   : TShark (Wireshark)")
    print(f"   Pipeline  : Blockchain + ML + SQLite")
    print("─" * 60)
    print("⏳ Starting capture (requires admin privileges)…\n")

    try:
        capture = pyshark.LiveCapture(interface=INTERFACE)
    except Exception as e:
        print(f"❌ Could not open interface '{INTERFACE}': {e}")
        print("   → Run as Administrator")
        print("   → Or set CAPTURE_INTERFACE env var to your adapter name")
        sys.exit(1)

    packet_count = 0

    try:
        for packet in capture.sniff_continuously():
            packet_count += 1

            log_line, proto = format_packet(packet)
            if log_line:
                print(f"📡 [{packet_count:>6}] {log_line}")
                store_log(log_line)

            process_packet(packet)

    except KeyboardInterrupt:
        print(f"\n\n🛑 Capture stopped. {packet_count} packets processed.")
    except Exception as e:
        print(f"\n❌ Capture error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()