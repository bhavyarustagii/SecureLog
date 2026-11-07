# SecureLog – AI-Powered Security Monitoring Platform

SecureLog is a hybrid security monitoring and forensic logging platform combining real-time network traffic packet inspection, machine learning anomaly detection, relational persistence, and blockchain-anchored tamper-evident evidence logging.

---

## Architecture Overview

SecureLog consists of five modular subsystems:

```
+--------------------------------------------------------------------------+
|                        SecureLog Architecture                            |
+--------------------------------------------------------------------------+
|                                                                          |
|   1. Ingestion Layer                                                     |
|      - TShark / PyShark live packet sniffing (Ethernet / Wi-Fi)           |
|      - Signature-based pattern matching (SQLi, XSS, Path Traversal)     |
|      - Heuristic packet inspection & port-scan detection                |
|                                                                          |
|   2. Detection & ML Engine                                               |
|      - Heuristic feature extractor (12 temporal & structural features)   |
|      - Scikit-learn Isolation Forest unsupervised anomaly scoring        |
|      - Keyword-based severity classification (Info, Warning, High, Crit) |
|                                                                          |
|   3. Persistence Layer                                                   |
|      - SQLite relational database (`events` table)                       |
|      - Legacy flat-file backup (`security_logs.txt`)                     |
|      - Modern modular repository abstraction (`app/services/storage`)    |
|                                                                          |
|   4. Blockchain Evidence Anchoring                                       |
|      - SHA-256 cryptographic hashing of security events                  |
|      - Solidity smart contract (`LogStorage.sol`) on Ethereum / Ganache |
|      - Tamper-evident on-chain verification                              |
|                                                                          |
|   5. User Interface & Alerting                                           |
|      - Streamlit SOC Operations Dashboard (`dashboard_advanced.py`)     |
|      - React + Vite modern SOC frontend (`frontend/`)                    |
|      - FastAPI REST endpoints (`api.py`)                                 |
|      - Asynchronous Telegram & SMTP alert dispatcher (`alerter.py`)      |
+--------------------------------------------------------------------------+
```

---

## Feature Implementation Status

To provide technical transparency, the table below reflects the exact implementation status in this codebase:

| Component | Status | Location | Description |
| :--- | :--- | :--- | :--- |
| **Isolation Forest** | Implemented | `ml_engine.py` | Unsupervised anomaly detector trained on heuristic feature vectors. |
| **Random Forest** | *Planned* | — | Supervised multi-class attack classification (planned). |
| **SVM / One-Class SVM** | *Planned* | — | Support Vector Machine anomaly detection (planned). |
| **LSTM Autoencoder** | *Planned* | — | Deep sequence autoencoder for reconstruction error (planned). |
| **Network Traffic Sniffer** | Implemented | `network_monitor.py`, `auto_logger.py` | Live packet sniffing via PyShark / TShark with protocol dissection. |
| **Modular Async Ingestor**| Implemented | `app/services/capture/` | Asynchronous streaming TShark capture with typed schema dataclasses. |
| **Signature Matching** | Implemented | `network_monitor.py` | Regular expression rules for SQLi, XSS, traversal, and scanner UAs. |
| **SQLite Persistence** | Implemented | `db_manager.py`, `app/services/storage/` | Relational storage for forensic logs, anomaly scores, and chain status. |
| **SHA-256 Ledger** | Implemented | `blockchain_logger.py`, `contract.sol` | Hashes log events and anchors hashes on Ethereum (Ganache) via Web3.py. |
| **Alerting Dispatcher** | Implemented | `alerter.py` | Multithreaded alerting via Telegram Bot API and SMTP Email with queue deduplication. |
| **Streamlit Dashboard** | Implemented | `dashboard_advanced.py` | SOC web console with threat feed, geolocation lookup, and metric charts. |
| **FastAPI REST API** | Implemented | `api.py` | Endpoints for event streaming and stats queries. |
| **React / Vite UI** | Implemented | `frontend/` | React dashboard with dark cyber SOC theme, charts, and threat tables. |
| **Docker Compose** | Implemented | `Dockerfile`, `docker-compose.yml` | Multi-container setup for Ganache, contract deployer, dashboard, and logger. |
| **AWS Cloud Deployment**| *Planned* | — | CloudFormation / Terraform templates for ECS/EKS deployment (planned). |

---

## Technology Stack

- **Core Backend**: Python 3.11, AsyncIO
- **Network Inspection**: Wireshark / TShark, PyShark
- **Machine Learning**: Scikit-Learn (Isolation Forest), NumPy, Pandas
- **Blockchain / Ledger**: Web3.py, Solidity (0.8.0), Ganache, Py-Solc-X
- **Storage**: SQLite3
- **Visualization**: Streamlit, Plotly, React (v19), Vite, Recharts, Lucide Icons
- **API**: FastAPI, Uvicorn, Pydantic
- **Containerization**: Docker, Docker Compose

---

## Prerequisites

1. **Python 3.11+**
2. **Wireshark / TShark**:
   - Windows: Install Wireshark and ensure `tshark.exe` is in `C:\Program Files\Wireshark\` or added to your system `PATH`.
   - Linux: `sudo apt-get install tshark libpcap-dev`
3. **Ganache** (for local blockchain logging):
   - Ganache GUI or Ganache CLI listening on `http://127.0.0.1:7545`
4. **Node.js 18+ & npm** (optional, for React frontend)

---

## Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/bhavyarustagii/SecureLog.git
cd SecureLog
```

### 2. Configure Environment & Python Virtual Environment
```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

# Install dependencies:
pip install -r requirements.txt
```

### 3. Configure Credentials (Optional)
Copy the template configuration files:
```bash
cp config.example.ini config.ini
cp .env.example .env
```
Edit `config.ini` or `.env` if you wish to enable email or Telegram alerting.

---

## Execution Guide

### Option A: Local Execution

1. **Start Ganache**:
   Ensure Ganache is running on `http://127.0.0.1:7545`.

2. **Deploy the Smart Contract**:
   ```bash
   python deploy_contract.py
   ```
   This compiles `contract.sol` and saves the contract address to `contract_address.txt`.

3. **Verify Connectivity**:
   ```bash
   python test_connection.py
   python test_blockchain.py
   ```

4. **Launch the Streamlit SOC Dashboard**:
   ```bash
   streamlit run dashboard_advanced.py
   ```
   Access the dashboard at `http://localhost:8501`.

5. **Start Packet Sniffing & Logging** (Run as Administrator for raw packet access):
   ```bash
   python auto_logger.py
   # OR run the network monitor directly:
   python network_monitor.py
   ```

6. **Simulate Attacks (Testing Mode)**:
   ```bash
   python attack_simulator.py --all
   ```

### Option B: Docker Compose
```bash
docker-compose up --build
```
This spins up:
- `securelog_ganache`: Local Ethereum blockchain on port 7545
- `securelog_deployer`: One-time contract deployer
- `securelog_dashboard`: Streamlit dashboard on port 8501
- `securelog_logger`: Background packet capture and logger

---

## Current Limitations & Notes

- **Network Interface**: In `network_monitor.py` and `auto_logger.py`, the default interface is configured as `"Wi-Fi"`. If using an Ethernet adapter or Linux interface (`eth0`), set the `CAPTURE_INTERFACE` environment variable accordingly.
- **Root / Administrator Privileges**: Capturing live promiscuous packets and blocking IPs via firewall requires Administrator privileges on Windows or `sudo` / `CAP_NET_RAW` capabilities on Linux.
- **Model Training**: The current `ml_engine.py` Isolation Forest model is seeded with synthetic templates upon initial database setup; external benchmark dataset training (e.g., CIC-IDS2017) is planned.
- **Cloud Infrastructure**: Cloud deployment configurations for AWS are planned for future releases.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
