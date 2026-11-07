"""Standardized Benchmark Dataset Generator for SecureLog.

Generates ground-truth labelled cybersecurity event datasets combining:
1. Log text representations (for evaluating the existing ml_engine heuristic pipeline)
2. Network packet flow metadata (for evaluating advanced flow-based models and storage)
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

# Representative benign event templates
BENIGN_TEMPLATES = [
    ("Admin login success from {src_ip}", "login_success"),
    ("Normal user session initiated from {src_ip} for user_{uid}", "user_session"),
    ("Scheduled backup completed successfully to /backup/daily_{uid}.tar.gz", "backup"),
    ("Config reload triggered by internal service from {src_ip}", "config_reload"),
    ("Routine health check passed on port 8080", "health_check"),
    ("Database connection pool refreshed: 25 active connections", "db_pool"),
    ("User {uid} accessed report document at /reports/q4_summary.pdf", "doc_access"),
    ("GET /index.html HTTP/1.1 200 OK from {src_ip}", "http_normal"),
    ("GET /api/v1/status HTTP/1.1 200 OK from {src_ip}", "api_normal"),
    ("POST /api/v1/telemetry HTTP/1.1 204 No Content from {src_ip}", "telemetry"),
    ("TLS handshake completed with client {src_ip} cipher=ECDHE-RSA-AES256-GCM-SHA384", "tls_handshake"),
    ("DNS Query: api.github.com resolved to 140.82.121.4 from {src_ip}", "dns_query"),
    ("NTP time synchronization successful with pool.ntp.org", "ntp_sync"),
    ("SSH connection established for deploy-user from {src_ip} on port 22", "ssh_normal"),
]

# Attack templates by category
ATTACK_TEMPLATES = {
    "sql_injection": [
        ("SQL injection attempt detected from {src_ip} -> payload: 1' OR '1'='1 --", 3),
        ("SQL injection attempt blocked from {src_ip} -> payload: UNION SELECT null, username, password FROM users", 3),
        ("SQL injection attempt: xp_cmdshell('whoami') detected from {src_ip}", 3),
        ("POST /api/login HTTP/1.1 400 Bad Request: admin' or 1=1-- from {src_ip}", 3),
    ],
    "xss": [
        ("XSS payload detected in HTTP request from {src_ip} -> payload: <script>alert(1)</script>", 3),
        ("XSS attack blocked from {src_ip} -> payload: <iframe src='javascript:alert(document.cookie)'>", 3),
        ("XSS attempt: onerror=alert(document.domain) from {src_ip} in query parameter 'q'", 3),
    ],
    "port_scan": [
        ("Possible Port Scan from {src_ip} (65 packets across 45 ports in 2 seconds)", 2),
        ("SYN scan detected from {src_ip} targeting ports 21, 22, 23, 80, 443, 3306, 8080", 2),
        ("Nmap OS fingerprinting scan detected from {src_ip}", 2),
    ],
    "brute_force": [
        ("Multiple SSH failures detected from {src_ip} (25 failed attempts in 60s)", 3),
        ("Brute-force attack detected on port 22 from {src_ip} targeting user root", 3),
        ("Failed login attempt from {src_ip} for admin (attempt 8 of 10)", 2),
        ("HTTP Basic Auth brute force detected from {src_ip} (40 requests/sec)", 3),
    ],
    "ddos": [
        ("DDoS traffic spike from {src_ip}: 15000 pps UDP flood detected", 4),
        ("SYN flood attack detected from {src_ip} on port 443: queue threshold exceeded", 4),
        ("DDoS amplification attack detected targeting DNS service from {src_ip}", 4),
    ],
    "path_traversal": [
        ("Path traversal attempt detected from {src_ip} -> payload: ../../../etc/passwd", 3),
        ("Path traversal blocked from {src_ip} -> payload: ..%2f..%2fwindows%2fsystem.ini", 3),
    ],
    "malware": [
        ("Malware signature detected in payload from {src_ip} matching Win32.Trojan.Agent", 4),
        ("Ransomware pattern detected from {src_ip}: bulk file encryption activity flagged", 4),
        ("Suspicious outbound connection to known C2 server {src_ip}:8443", 3),
    ]
}


def _random_ip(private: bool = False) -> str:
    if private:
        return f"192.168.1.{random.randint(2, 254)}"
    return f"{random.randint(11, 210)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_benchmark_dataset(
    n_samples: int = 5000,
    attack_ratio: float = 0.20,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Generate a balanced, realistic, labelled benchmark dataset.
    
    Args:
        n_samples: Total number of event records.
        attack_ratio: Proportion of attack instances (e.g. 0.20 = 20% attacks, 80% benign).
        seed: Random seed for deterministic reproducibility.
        
    Returns:
        List of event dictionaries containing log_text, timestamp, label, attack_type, and packet fields.
    """
    random.seed(seed)
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks

    dataset: list[dict[str, Any]] = []
    base_time = datetime(2026, 11, 1, 0, 0, 0)
    attack_categories = list(ATTACK_TEMPLATES.keys())

    # Generate Benign Samples
    for i in range(n_benign):
        tmpl, event_subtype = random.choice(BENIGN_TEMPLATES)
        src_ip = _random_ip(private=random.random() < 0.7)
        uid = f"user_{random.randint(100, 999)}"
        log_text = tmpl.format(src_ip=src_ip, uid=uid)
        
        ts = base_time + timedelta(seconds=random.randint(0, 7 * 86400))
        
        dataset.append({
            "id": i + 1,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "log_text": log_text,
            "label": 0,  # 0 = Benign
            "attack_type": "benign",
            "subtype": event_subtype,
            "source_ip": src_ip,
            "dest_ip": "10.0.0.1",
            "protocol": "TCP" if "HTTP" in log_text or "SSH" in log_text else ("UDP" if "DNS" in log_text or "NTP" in log_text else "TCP"),
            "src_port": random.randint(1024, 65535),
            "dst_port": 80 if "HTTP" in log_text else (22 if "SSH" in log_text else (53 if "DNS" in log_text else 443)),
            "packet_size": random.randint(64, 1500),
            "tcp_flags": "ACK" if random.random() < 0.6 else "PSH,ACK",
        })

    # Generate Attack Samples
    for i in range(n_attacks):
        category = random.choice(attack_categories)
        tmpl, expected_sev = random.choice(ATTACK_TEMPLATES[category])
        src_ip = _random_ip(private=random.random() < 0.1)
        log_text = tmpl.format(src_ip=src_ip)
        
        ts = base_time + timedelta(seconds=random.randint(0, 7 * 86400))
        
        dst_port = 80
        protocol = "TCP"
        if category == "brute_force":
            dst_port = 22
        elif category == "ddos":
            protocol = random.choice(["UDP", "TCP"])
            dst_port = 443 if protocol == "TCP" else 53
        elif category == "port_scan":
            dst_port = random.choice([21, 22, 23, 80, 443, 3306, 8080])

        dataset.append({
            "id": n_benign + i + 1,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "log_text": log_text,
            "label": 1,  # 1 = Attack / Anomaly
            "attack_type": category,
            "subtype": category,
            "source_ip": src_ip,
            "dest_ip": "10.0.0.1",
            "protocol": protocol,
            "src_port": random.randint(1024, 65535),
            "dst_port": dst_port,
            "packet_size": random.randint(40, 4096),
            "tcp_flags": "SYN" if category in ("port_scan", "ddos") else "PSH,ACK",
        })

    random.shuffle(dataset)
    for idx, sample in enumerate(dataset):
        sample["id"] = idx + 1

    return dataset
