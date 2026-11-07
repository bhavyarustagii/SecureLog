from web3 import Web3
import hashlib
import json
import os
from datetime import datetime

try:
    from db_manager import init_db, insert_event, mark_on_chain, update_anomaly_score
    init_db()
    _DB_AVAILABLE = True
except Exception as _db_err:
    print(f"[WARN] db_manager not available: {_db_err}")
    _DB_AVAILABLE = False

try:
    from ml_engine import score as ml_score
    _ML_AVAILABLE = True
except Exception as _ml_err:
    print(f"[WARN] ml_engine not available: {_ml_err}")
    _ML_AVAILABLE = False

try:
    from alerter import send_alert
    _ALERTER_AVAILABLE = True
except Exception as _al_err:
    print(f"[WARN] alerter not available: {_al_err}")
    _ALERTER_AVAILABLE = False

GANACHE_URL = os.environ.get("GANACHE_URL", "http://127.0.0.1:7545")
LOG_FILE = "security_logs.txt"

CONTRACT_ADDRESS = "0x3EFa03B66F8e3d8D8D4590b68E2298F16fA1E0ED"
contract_file = "/data/contract_address.txt" if os.path.isdir("/data") else "contract_address.txt"
if os.path.exists(contract_file):
    with open(contract_file, "r") as f:
        CONTRACT_ADDRESS = f.read().strip()

ABI = [
    {
        "inputs": [{"internalType": "string", "name": "hash", "type": "string"}],
        "name": "storeLog",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "name": "getLog",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getTotalLogs",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "name": "logs",
        "outputs": [
            {"internalType": "uint256", "name": "id", "type": "uint256"},
            {"internalType": "string", "name": "hash", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

web3 = None
contract = None
account = None

def _connect():
    global web3, contract, account
    try:
        web3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        if web3.is_connected():
            contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)
            account = web3.eth.accounts[0]
            return True
        else:
            print("[WARN] Ganache not reachable at", GANACHE_URL)
            return False
    except Exception as e:
        print(f"[WARN] Could not connect to Ganache: {e}")
        return False

_connected = _connect()


def is_connected():
    global _connected
    if _connected and web3 and web3.is_connected():
        return True
    _connected = _connect()
    return _connected


def store_log(log):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {log}\n")
    except Exception as e:
        print(f"[ERROR] Could not write to {LOG_FILE}: {e}")

    row_id = None
    severity_label = "🔵 Info"
    severity_lvl   = 1
    if _DB_AVAILABLE:
        try:
            from db_manager import _classify
            severity_label, severity_lvl = _classify(log)
            row_id = insert_event(log, on_chain=False)
        except Exception as e:
            print(f"[WARN] DB insert failed: {e}")

    hash_value = hashlib.sha256(log.encode()).hexdigest()
    print(f"Hash: {hash_value}")
    chain_ok = False

    if is_connected():
        try:
            tx = contract.functions.storeLog(hash_value).transact({'from': account})
            web3.eth.wait_for_transaction_receipt(tx)
            print("✅ Stored on blockchain")
            chain_ok = True
            if _DB_AVAILABLE and row_id:
                mark_on_chain(row_id)
        except Exception as e:
            print(f"[WARN] Blockchain write failed: {e}")
    else:
        print("[INFO] Blockchain unavailable – log saved locally only")

    anomaly = None
    if _ML_AVAILABLE:
        try:
            anomaly = ml_score(log, timestamp)
            if anomaly is not None:
                risk = "⚠️ ANOMALY" if anomaly < 0 else "Normal"
                print(f"[ML] Score: {anomaly:.4f} ({risk})")
                if _DB_AVAILABLE and row_id:
                    update_anomaly_score(row_id, anomaly)
        except Exception as e:
            print(f"[WARN] ML scoring failed: {e}")

    if _ALERTER_AVAILABLE and severity_lvl >= 3:
        try:
            send_alert(
                log_text      = log,
                severity      = severity_label,
                severity_lvl  = severity_lvl,
                anomaly_score = anomaly,
                async_send    = True,
            )
        except Exception as e:
            print(f"[WARN] Alert failed: {e}")


def get_total_logs():
    if is_connected():
        try:
            return contract.functions.getTotalLogs().call()
        except Exception as e:
            print(f"[WARN] Could not read total logs: {e}")
    return -1


def get_log(index):
    if is_connected():
        try:
            return contract.functions.getLog(index).call()
        except Exception as e:
            print(f"[WARN] Could not read log at index {index}: {e}")
    return None