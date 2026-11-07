import re
import time
from collections import defaultdict
from datetime import datetime

from blockchain_logger import store_log
import subprocess
import threading

BLOCKED_IPS = set()

def block_ip(ip: str):
    if ip in BLOCKED_IPS or ip.startswith("127."):
        return
    try:
        print(f"🛑 [FIREWALL] Blocking IP {ip}...")
        # Run asynchronously to avoid blocking packet processing
        def _block():
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", 
                     f"name=SecureLog_Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                BLOCKED_IPS.add(ip)
                _log_event(f"Firewall blocked malicious IP: {ip}")
            except Exception as e:
                print(f"⚠️ [WARN] Failed to block IP {ip} (Admin rights required)")
        threading.Thread(target=_block, daemon=True).start()
    except Exception:
        pass

INTERFACE        = "Wi-Fi"
SCAN_THRESHOLD   = 20
ALERT_INTERVAL   = 30
PAYLOAD_MAX_LEN  = 4096

SQL_PATTERNS = re.compile(
    r"('|\%27)\s*(or|OR|and|AND)\s*('|\%27|1\s*=\s*1)"
    r"|union\s+select"
    r"|drop\s+table"
    r"|insert\s+into"
    r"|select\s+.*\s+from"
    r"|xp_cmdshell"
    r"|;--"
    r"|\bexec\s*\(",
    re.IGNORECASE,
)

XSS_PATTERNS = re.compile(
    r"<script[\s>]"
    r"|javascript\s*:"
    r"|onerror\s*="
    r"|onload\s*="
    r"|eval\s*\("
    r"|document\.cookie"
    r"|alert\s*\("
    r"|<iframe[\s>]",
    re.IGNORECASE,
)

TRAVERSAL_PATTERNS = re.compile(
    r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\./",
    re.IGNORECASE,
)

SCANNER_UA_PATTERNS = re.compile(
    r"nmap|sqlmap|nikto|masscan|zgrab|hydra|metasploit|openvas|dirbuster|gobuster",
    re.IGNORECASE,
)

SUSPICIOUS_HTTP_METHODS = {"TRACE", "TRACK", "DEBUG", "CONNECT"}

connection_counter = defaultdict(int)
ssh_counter        = defaultdict(int)
last_alert_time    = {}


def _can_alert(src: str) -> bool:
    now = time.time()
    if src not in last_alert_time or now - last_alert_time[src] > ALERT_INTERVAL:
        last_alert_time[src] = now
        return True
    return False


def _log_event(event: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"🚨 [{ts}] SECURITY EVENT: {event}")
    store_log(event)


def _inspect_payload(payload: bytes, src: str, dst_port: int):
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return

    if SQL_PATTERNS.search(text):
        if _can_alert(src):
            snippet = text[:120].replace("\n", " ")
            _log_event(f"SQL injection attempt detected from {src} -> payload: {snippet}")
            block_ip(src)

    if XSS_PATTERNS.search(text):
        if _can_alert(src):
            snippet = text[:120].replace("\n", " ")
            _log_event(f"XSS payload detected in HTTP request from {src} -> payload: {snippet}")
            block_ip(src)

    if TRAVERSAL_PATTERNS.search(text):
        if _can_alert(src):
            snippet = text[:120].replace("\n", " ")
            _log_event(f"Path traversal attempt detected from {src} -> payload: {snippet}")
            block_ip(src)

    if SCANNER_UA_PATTERNS.search(text):
        if _can_alert(src):
            _log_event(f"Known scanner/exploit tool detected from {src}")

    first_line = text.split("\n")[0].strip()
    method = first_line.split(" ")[0].upper() if first_line else ""
    if method in SUSPICIOUS_HTTP_METHODS:
        if _can_alert(src):
            _log_event(f"Suspicious HTTP method '{method}' from {src}")


def process_packet(packet):
    try:
        if not hasattr(packet, "ip"):
            return

        src      = packet.ip.src
        dst_port = None

        if hasattr(packet, "tcp"):
            try:
                dst_port = int(packet.tcp.dstport)
            except Exception:
                pass
        elif hasattr(packet, "udp"):
            try:
                dst_port = int(packet.udp.dstport)
            except Exception:
                pass

        connection_counter[src] += 1
        if connection_counter[src] > SCAN_THRESHOLD:
            if _can_alert(src):
                _log_event(f"Possible Port Scan from {src} ({connection_counter[src]} packets)")
                block_ip(src)

        if dst_port == 22:
            ssh_counter[src] += 1
            if ssh_counter[src] > 10 and _can_alert(src):
                _log_event(f"Brute-force SSH detected from {src} ({ssh_counter[src]} attempts)")
                block_ip(src)

        if hasattr(packet, "tcp") and hasattr(packet.tcp, "payload"):
            try:
                raw = bytes.fromhex(
                    packet.tcp.payload.replace(":", "")
                )[:PAYLOAD_MAX_LEN]
                _inspect_payload(raw, src, dst_port)
            except Exception:
                pass

    except AttributeError:
        pass
    except Exception as e:
        print(f"[WARN] Packet processing error: {e}")


if __name__ == "__main__":
    try:
        import pyshark
    except ImportError:
        print("❌ pyshark not installed. Run: pip install pyshark")
        raise SystemExit(1)

    print(f"🔍 SecureLog Advanced Network Monitor")
    print(f"   Interface : {INTERFACE}")
    print(f"   Detects   : Port Scan, SQL Injection, XSS, Path Traversal,")
    print(f"               SSH Brute-force, Scanner UAs, Suspicious HTTP verbs")
    print(f"   Threshold : {SCAN_THRESHOLD} packets / alert interval: {ALERT_INTERVAL}s")
    print("─" * 60)

    capture = pyshark.LiveCapture(interface=INTERFACE)

    try:
        for packet in capture.sniff_continuously():
            process_packet(packet)
    except KeyboardInterrupt:
        print("\n[INFO] Network monitor stopped by user.")