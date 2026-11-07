import requests
import socket
import time
import argparse
import sys

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8501

def simulate_sqli():
    print(f"[*] Simulating SQL Injection against {TARGET_IP}...")
    url = f"http://{TARGET_IP}:{TARGET_PORT}/?id=1"
    payload = "1' OR '1'='1"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        requests.get(url, params={"id": payload}, headers=headers, timeout=2)
        print("    [+] SQLi payload sent successfully.")
    except Exception as e:
        print(f"    [-] Error sending payload: {e}")

def simulate_xss():
    print(f"[*] Simulating XSS attack against {TARGET_IP}...")
    url = f"http://{TARGET_IP}:{TARGET_PORT}/"
    payload = "<script>alert(1)</script>"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        requests.get(url, params={"q": payload}, headers=headers, timeout=2)
        print("    [+] XSS payload sent successfully.")
    except Exception as e:
        print(f"    [-] Error sending payload: {e}")

def simulate_port_scan():
    print(f"[*] Simulating Port Scan against {TARGET_IP}...")
    ports = [21, 22, 23, 80, 443, 3306, 8080, 8443, 8501]
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                s.connect((TARGET_IP, port))
        except Exception:
            pass
    print("    [+] Port scan simulation completed.")

def simulate_ssh_brute():
    print(f"[*] Simulating SSH Brute-force against {TARGET_IP}...")
    for _ in range(12):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                s.connect((TARGET_IP, 22))
        except Exception:
            pass
    print("    [+] SSH brute-force simulation completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureLog Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--all", action="store_true", help="Run all simulations")
    parser.add_argument("--sqli", action="store_true", help="Simulate SQLi")
    parser.add_argument("--xss", action="store_true", help="Simulate XSS")
    parser.add_argument("--scan", action="store_true", help="Simulate Port Scan")
    parser.add_argument("--ssh", action="store_true", help="Simulate SSH Brute-force")

    args = parser.parse_args()
    TARGET_IP = args.target

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    if args.all or args.sqli:
        simulate_sqli()
        time.sleep(1)
    if args.all or args.xss:
        simulate_xss()
        time.sleep(1)
    if args.all or args.scan:
        simulate_port_scan()
        time.sleep(1)
    if args.all or args.ssh:
        simulate_ssh_brute()
        time.sleep(1)
    
    print("\n[+] Simulation finished. Check SecureLog Dashboard for alerts.")
