import os
import sys
import requests
import hashlib

LOG_FILE = "security_logs.txt"
GANACHE_URL = "http://127.0.0.1:7545"
DASHBOARD_FILE = "dashboard_advanced.py"

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  ✅ PASS  {name}")
        passed += 1
    else:
        msg = f"  ❌ FAIL  {name}"
        if detail:
            msg += f"  –  {detail}"
        print(msg)
        failed += 1


print("=" * 55)
print("  SecureLog – Connection & Health Checks")
print("=" * 55)

print("\n[1] Log File")
check("Log file exists", os.path.exists(LOG_FILE), f"{LOG_FILE} not found")

try:
    with open(LOG_FILE, "a") as f:
        f.write("")
    check("Log file writable", True)
except Exception as e:
    check("Log file writable", False, str(e))

try:
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    check("Log file readable", True)
    print(f"       ↳ {len(lines)} log entries found")
except Exception as e:
    check("Log file readable", False, str(e))

print("\n[2] Ganache Blockchain")
ganache_ok = False
try:
    from web3 import Web3
    _w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    ganache_ok = _w3.is_connected()
    check("Ganache reachable", ganache_ok, f"Web3 connected via JSON-RPC")
except Exception as e:
    check("Ganache reachable", False, str(e))

print("\n[3] Smart Contract")
if ganache_ok:
    try:
        from web3 import Web3
        web3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        check("Web3 connected", web3.is_connected())

        from blockchain_logger import ABI, CONTRACT_ADDRESS
        contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)
        total = contract.functions.getTotalLogs().call()
        check("Contract callable", True)
        print(f"       ↳ {total} logs stored on-chain")
    except Exception as e:
        check("Contract callable", False, str(e))
else:
    print("  ⏭️  Skipped (Ganache offline)")


print("\n[4] Dashboard")
check("Dashboard file exists", os.path.exists(DASHBOARD_FILE))

print("\n[5] blockchain_logger Module")
try:
    from blockchain_logger import store_log, is_connected, get_total_logs
    check("Module importable", True)
    check("is_connected()", is_connected() or not ganache_ok,
          "Expected connected" if ganache_ok else "Ganache offline – OK")
except Exception as e:
    check("Module importable", False, str(e))

print("\n" + "=" * 55)
total = passed + failed
print(f"  Results: {passed}/{total} passed, {failed}/{total} failed")
if failed == 0:
    print(" All checks passed!")
else:
    print("   Some checks failed – see details above")
print("=" * 55)
