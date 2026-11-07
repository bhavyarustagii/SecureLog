import random
import time
from datetime import datetime

LOG_FILE = "security_logs.txt"

SAMPLE_LOGS = [
    "Failed login attempt from 192.168.1.10",
    "Admin login success from 192.168.1.1",
    "Firewall blocked suspicious IP 203.0.113.45",
    "Multiple failed SSH attempts from 10.0.0.5",
    "Possible port scan detected from 172.16.0.99",
    "Brute-force attack on port 22 from 198.51.100.12",
    "DDoS traffic spike from 192.0.2.77",
    "Malware signature detected from 203.0.113.88",
    "SQL injection attempt blocked from 198.51.100.33",
    "Unauthorized access attempt on /admin from 10.0.0.15",
    "Privilege escalation attempt from 192.168.1.25",
    "Ransomware pattern detected from 198.51.100.66",
]

print("🔄 Log Generator started – writing to", LOG_FILE)

while True:
    log = random.choice(SAMPLE_LOGS)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {log}"

    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

    print("📝 Generated:", entry)
    time.sleep(5)