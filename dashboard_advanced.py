import streamlit as st
import pandas as pd
import requests
import re
import os
import socket
import platform
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

LOG_FILE         = "security_logs.txt"
GANACHE_URL      = os.environ.get("GANACHE_URL", "http://127.0.0.1:7545")

CONTRACT_ADDRESS = "0x3EFa03B66F8e3d8D8D4590b68E2298F16fA1E0ED"
contract_file = "/data/contract_address.txt" if os.path.isdir("/data") else "contract_address.txt"
if os.path.exists(contract_file):
    with open(contract_file, "r") as f:
        CONTRACT_ADDRESS = f.read().strip()
REFRESH_SECONDS  = 10

try:
    from db_manager import (
        init_db, fetch_events, fetch_stats,
        get_total_count, migrate_from_txt
    )
    init_db()
    migrate_from_txt(LOG_FILE)
    _DB_OK = True
except Exception as _db_e:
    _DB_OK = False

try:
    from ml_engine import is_model_ready, auto_train_from_db
    if not is_model_ready():
        auto_train_from_db()
    _ML_OK = True
except Exception as _ml_e:
    _ML_OK = False

st.set_page_config(
    page_title="SecureNet SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

import streamlit_authenticator as stauth

credentials = {
    "usernames": {
        "admin": {
            "email": "admin@securenet.local",
            "first_name": "SOC",
            "last_name": "Admin",
            "password": "$2b$12$A6wreSMAT/YEvrgThpqyfesxBH3K/yOEjecU4fmmlE1pxmp9Ia9Vq"
        }
    }
}
authenticator = stauth.Authenticate(
    credentials,
    "securenet_dashboard",
    "secure_key",
    cookie_expiry_days=1
)

authenticator.login(location="main")

authentication_status = st.session_state.get("authentication_status")

if authentication_status is False:
    st.error("Username/password is incorrect")
    st.stop()
elif authentication_status is None:
    st.warning("Please enter your username and password (admin / admin123)")
    st.stop()


st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0a0e17 100%);
    }
    .main .block-container { padding-top: 1.5rem; }

    [data-testid="stMetric"] {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(99, 102, 241, 0.3);
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 0 20px rgba(99, 102, 241, 0.1);
    }
    [data-testid="stMetricLabel"] { color: #a5b4fc !important; }
    [data-testid="stMetricValue"] { color: #e0e7ff !important; font-weight: 700; }

    h1, h2, h3 { color: #e0e7ff !important; }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a 0%, #1e1b4b 100%);
        border-right: 1px solid rgba(99, 102, 241, 0.2);
    }
    .stDataFrame {
        border: 1px solid rgba(99, 102, 241, 0.2) !important;
        border-radius: 8px;
    }
    .stSuccess { background-color: rgba(16, 185, 129, 0.1) !important; border-left-color: #10b981 !important; }
    hr { border-color: rgba(99, 102, 241, 0.2) !important; }

    .anomaly-high   { color: #ef4444; font-weight: 700; }
    .anomaly-normal { color: #22d3ee; }

    .pill-ok   { background:#10b981; color:#fff; padding:2px 10px; border-radius:12px; font-size:0.78rem; }
    .pill-warn { background:#ef4444; color:#fff; padding:2px 10px; border-radius:12px; font-size:0.78rem; }
</style>
""", unsafe_allow_html=True)

IP_REGEX = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

SEVERITY_RULES = {
    "Ransomware":            ("🔴 Critical",  4),
    "Malware":               ("🔴 Critical",  4),
    "DDoS":                  ("🔴 Critical",  4),
    "Brute-force":           ("🟠 High",      3),
    "Privilege escalation":  ("🟠 High",      3),
    "SQL injection":         ("🟠 High",      3),
    "XSS":                   ("🟠 High",      3),
    "Path traversal":        ("🟠 High",      3),
    "Unauthorized access":   ("🟠 High",      3),
    "Port Scan":             ("🟡 Warning",   2),
    "port scan":             ("🟡 Warning",   2),
    "SSH":                   ("🟡 Warning",   2),
    "Firewall blocked":      ("🟡 Warning",   2),
    "Failed login":          ("🟡 Warning",   2),
    "Certificate mismatch":  ("🟡 Warning",   2),
    "Suspicious outbound":   ("🟡 Warning",   2),
}


def classify_severity(log_text):
    for keyword, (label, priority) in SEVERITY_RULES.items():
        if keyword.lower() in log_text.lower():
            return label, priority
    return "🔵 Info", 1


def check_ganache():
    try:
        r = requests.post(GANACHE_URL, json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}, timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def load_logs_txt():
    try:
        with open(LOG_FILE, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def extract_ips(logs):
    ips = []
    for log in logs:
        ips.extend(IP_REGEX.findall(log))
    return list(dict.fromkeys(ips))


def format_anomaly(score):
    if score is None:
        return "—"
    if score < -0.05:
        return f"⚠️ {score:.3f}"
    return f"✅ {score:.3f}"


ganache_status = check_ganache()
start_time     = datetime.now()

if _DB_OK:
    raw_events = fetch_events(limit=500)
    logs = [f"[{e['timestamp']}] {e['log_text']}" for e in raw_events]
    total_events = get_total_count()
else:
    raw_events   = []
    logs         = load_logs_txt()
    total_events = len(logs)

with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("SecureNet")
    st.caption("SOC Dashboard v3.0")
    st.divider()

    st.subheader("👤 System Profile")
    st.markdown(f"""
| Property | Value |
|----------|-------|
| **Hostname** | `{socket.gethostname()}` |
| **OS** | `{platform.system()} {platform.release()}` |
| **Python** | `{platform.python_version()}` |
| **Dashboard Up** | `{start_time.strftime('%H:%M:%S')}` |
""")
    authenticator.logout("Logout", "main")

    st.divider()
    st.subheader("🔗 Connections")

    if ganache_status:
        st.success("Ganache: Connected")
    else:
        st.error("Ganache: Offline")

    db_status = "✅ SQLite" if _DB_OK else "⚠️ Flat file"
    ml_status = "✅ Ready"  if _ML_OK else "⚠️ Not trained"

    st.info(f"Storage: {db_status}")
    st.info(f"ML Engine: {ml_status}")

    log_file_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
    st.info(f"Log Backup: {log_file_size:,} bytes")
    st.code(f"Contract:\n{CONTRACT_ADDRESS}", language="text")

    st.divider()
    st.subheader("⚙️ Settings")
    auto_refresh = st.toggle("Auto-Refresh", value=True)
    max_rows     = st.slider("Max rows in feed", 10, 200, 50)
    show_ml      = st.toggle("Show ML Anomaly Scores", value=True)
    min_sev      = st.selectbox(
        "Min Severity Filter",
        ["All", "🟡 Warning+", "🟠 High+", "🔴 Critical"],
        index=0,
    )

st.markdown("""
# 🛡️ SecureNet SOC Dashboard
**Blockchain-backed Intrusion Detection & Forensic Logging** — v3.0 with ML & SQLite
""")
st.divider()

critical_count = sum(1 for l in logs if classify_severity(l)[1] >= 4)
high_count     = sum(1 for l in logs if classify_severity(l)[1] == 3)

if _DB_OK and raw_events:
    anomalies_count = sum(1 for e in raw_events if e.get("anomaly_score") is not None and e["anomaly_score"] < 0)
else:
    anomalies_count = 0

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("🚨 Total Events",    f"{total_events:,}")
col2.metric("🔴 Critical",        critical_count)
col3.metric("🟠 High",            high_count)
col4.metric("🤖 ML Anomalies",    anomalies_count)
col5.metric("⛓️ Blockchain",      "Active ✅" if ganache_status else "Offline ⚠️")

st.divider()

st.subheader("📡 Live Threat Feed")

sev_filter_map = {"All": 1, "🟡 Warning+": 2, "🟠 High+": 3, "🔴 Critical": 4}
min_sev_lvl    = sev_filter_map.get(min_sev, 1)

if _DB_OK and raw_events:
    filtered = [e for e in raw_events if e["severity_lvl"] >= min_sev_lvl][:max_rows]
    data = []
    for e in filtered:
        a_score = e.get("anomaly_score")
        data.append({
            "Time":      e["timestamp"],
            "Severity":  e["severity"],
            "Event":     e["log_text"][:120],
            "Source IP": e.get("source_ip") or "—",
            "Evidence":  "🔗 On-chain" if e["on_chain"] else "📄 Local",
            "ML Score":  format_anomaly(a_score) if show_ml else "—",
        })
else:
    display_logs = logs[-max_rows:]
    data = []
    for log in display_logs:
        sev_label, sev_lvl = classify_severity(log)
        if sev_lvl < min_sev_lvl:
            continue
        ts_match  = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', log)
        timestamp = ts_match.group(1) if ts_match else "—"
        event_text = log[len(ts_match.group(0)):].strip() if ts_match else log
        found_ips  = IP_REGEX.findall(log)
        data.append({
            "Time":      timestamp,
            "Severity":  sev_label,
            "Event":     event_text[:120],
            "Source IP": found_ips[0] if found_ips else "—",
            "Evidence":  "🔗 On-chain" if ganache_status else "📄 Local",
            "ML Score":  "—",
        })

df = pd.DataFrame(data)

if not df.empty:
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Severity":  st.column_config.TextColumn(width="small"),
            "Time":      st.column_config.TextColumn(width="medium"),
            "Source IP": st.column_config.TextColumn(width="small"),
            "Evidence":  st.column_config.TextColumn(width="small"),
            "ML Score":  st.column_config.TextColumn(width="small"),
        },
    )
else:
    st.info("No threat events yet. Run `auto_logger.py` or `network_monitor.py` to generate logs.")

st.divider()

if _DB_OK and show_ml and raw_events:
    scored_events = [e for e in raw_events if e.get("anomaly_score") is not None]

    if scored_events:
        st.subheader("🤖 ML Anomaly Analysis")

        scores = [e["anomaly_score"] for e in scored_events]
        labels = ["⚠️ Anomaly" if s < 0 else "✅ Normal" for s in scores]

        col_ml1, col_ml2 = st.columns([2, 1])

        with col_ml1:
            ml_df = pd.DataFrame({"Score": scores, "Classification": labels})
            fig_hist = px.histogram(
                ml_df, x="Score", color="Classification",
                nbins=40,
                color_discrete_map={"⚠️ Anomaly": "#ef4444", "✅ Normal": "#22d3ee"},
                template="plotly_dark",
                title="Anomaly Score Distribution",
            )
            fig_hist.add_vline(x=0, line_dash="dash", line_color="#f97316",
                               annotation_text="Anomaly threshold")
            fig_hist.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=20, r=20, t=40, b=20),
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        with col_ml2:
            n_anom = labels.count("⚠️ Anomaly")
            n_norm = labels.count("✅ Normal")
            fig_donut = px.pie(
                names=["Anomaly", "Normal"],
                values=[n_anom, n_norm],
                hole=0.55,
                color_discrete_sequence=["#ef4444", "#22d3ee"],
                template="plotly_dark",
                title="Anomaly Ratio",
            )
            fig_donut.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=40, b=10),
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        top_anomalies = sorted(scored_events, key=lambda e: e["anomaly_score"])[:10]
        if top_anomalies:
            st.markdown("**🔎 Top 10 Most Anomalous Events**")
            anom_df = pd.DataFrame([{
                "Score":    f"{e['anomaly_score']:.4f}",
                "Severity": e["severity"],
                "Time":     e["timestamp"],
                "Event":    e["log_text"][:100],
            } for e in top_anomalies])
            st.dataframe(anom_df, use_container_width=True, hide_index=True)

        st.divider()

st.subheader("📊 Threat Distribution")

attack_categories = {
    "Port Scan": 0, "SSH / Brute-force": 0, "DDoS": 0,
    "Malware / Ransomware": 0, "Injection / XSS": 0,
    "Unauthorized Access": 0, "Firewall Block": 0, "Other": 0,
}

for log in logs:
    lower = log.lower()
    if "port scan" in lower:
        attack_categories["Port Scan"] += 1
    elif "ssh" in lower or "brute" in lower:
        attack_categories["SSH / Brute-force"] += 1
    elif "ddos" in lower:
        attack_categories["DDoS"] += 1
    elif "malware" in lower or "ransomware" in lower:
        attack_categories["Malware / Ransomware"] += 1
    elif "injection" in lower or "xss" in lower or "traversal" in lower:
        attack_categories["Injection / XSS"] += 1
    elif "unauthorized" in lower or "privilege" in lower:
        attack_categories["Unauthorized Access"] += 1
    elif "firewall" in lower:
        attack_categories["Firewall Block"] += 1
    else:
        attack_categories["Other"] += 1

stats_df = pd.DataFrame({
    "Attack Type": list(attack_categories.keys()),
    "Count":       list(attack_categories.values()),
})

col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    fig_bar = px.bar(
        stats_df, x="Attack Type", y="Count", color="Attack Type",
        color_discrete_sequence=px.colors.qualitative.Set2,
        template="plotly_dark",
    )
    fig_bar.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False, margin=dict(l=20, r=20, t=30, b=20),
    )
    st.plotly_chart(fig_bar, use_container_width=True)

with col_chart2:
    non_zero = stats_df[stats_df["Count"] > 0]
    if not non_zero.empty:
        fig_pie = px.pie(
            non_zero, names="Attack Type", values="Count", hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Set2,
            template="plotly_dark",
        )
        fig_pie.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=20, r=20, t=30, b=20),
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No data for pie chart yet.")

st.divider()

unique_ips = extract_ips(logs)
public_ips = [
    ip for ip in unique_ips
    if not ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.",
                          "172.24.", "172.25.", "172.26.", "172.27.",
                          "172.28.", "172.29.", "172.30.", "172.31.",
                          "192.168.", "127.", "0."))
]

locations = []
for ip in public_ips[:10]:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if r.get("status") == "success":
            locations.append({
                "ip": ip, "lat": r["lat"], "lon": r["lon"],
                "country": r["country"], "city": r.get("city", "—"),
            })
    except Exception:
        pass

if locations:
    st.subheader("🌍 Attacker Geolocation Map")
    map_df = pd.DataFrame(locations)
    st.map(map_df, latitude="lat", longitude="lon")
    st.dataframe(
        map_df.rename(columns={"ip": "IP", "country": "Country",
                                "city": "City", "lat": "Lat", "lon": "Lon"}),
        use_container_width=True, hide_index=True,
    )
    st.divider()

st.subheader("⛓️ Blockchain Evidence Log")

if logs:
    evidence_logs = logs[-10:]
    for log in reversed(evidence_logs):
        severity_label, priority = classify_severity(log)
        if priority >= 4:
            st.error(f"🔗 Evidence Anchored: {log}")
        elif priority == 3:
            st.warning(f"🔗 Evidence Anchored: {log}")
        else:
            st.success(f"🔗 Evidence Anchored: {log}")
else:
    st.info("No evidence logs yet.")

st.divider()

st.caption(
    "SecureNet v3.0 • Blockchain + ML + SQLite Intrusion Detection & Forensic Logging System"
)

if auto_refresh:
    import time
    time.sleep(REFRESH_SECONDS)
    st.rerun()