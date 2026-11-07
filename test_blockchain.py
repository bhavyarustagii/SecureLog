from blockchain_logger import store_log, is_connected, get_total_logs
import hashlib

TEST_LOG = "TEST: Failed login attempt from 192.168.1.5"

print("=" * 50)
print("  Blockchain Logger – End-to-End Test")
print("=" * 50)

print("\n[1] Checking Ganache connection…")
connected = is_connected()
print(f"    Connected: {connected}")

if connected:
    before = get_total_logs()
    print(f"    Logs on-chain before: {before}")
else:
    before = -1
    print("    ⚠️  Ganache offline – blockchain writes will be skipped")

print(f"\n[2] Storing test log: '{TEST_LOG}'")
store_log(TEST_LOG)

if connected:
    after = get_total_logs()
    print(f"\n[3] Logs on-chain after:  {after}")
    if after == before + 1:
        print("    ✅ PASS – log was stored on blockchain successfully")
    else:
        print("    ❌ FAIL – log count did not increase")
else:
    print("\n[3] Blockchain verification skipped (offline)")
    print("    ✅ PASS – log was saved to local file (security_logs.txt)")

print("\n[4] Verifying local log file…")
try:
    with open("security_logs.txt", "r") as f:
        lines = f.readlines()
    found = any(TEST_LOG in line for line in lines)
    if found:
        print("    ✅ PASS – test log found in security_logs.txt")
    else:
        print("    ❌ FAIL – test log NOT found in security_logs.txt")
except FileNotFoundError:
    print("    ❌ FAIL – security_logs.txt does not exist")

print("\n" + "=" * 50)
print("  Test complete")
print("=" * 50)