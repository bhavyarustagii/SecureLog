import os
import configparser
import smtplib
import threading
from email.mime.text import MIMEText
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.ini")

_DEFAULT_MIN_LEVEL = 3


def _load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        cfg.read(CONFIG_PATH, encoding="utf-8")
    return cfg


def _ensure_config():
    if not os.path.exists(CONFIG_PATH):
        cfg = configparser.ConfigParser()
        cfg["telegram"] = {
            "bot_token":  "YOUR_BOT_TOKEN_HERE",
            "chat_id":    "YOUR_CHAT_ID_HERE",
            "min_level":  "3",
            "enabled":    "false",
        }
        cfg["email"] = {
            "enabled":    "false",
            "smtp_host":  "smtp.gmail.com",
            "smtp_port":  "587",
            "sender":     "your@gmail.com",
            "password":   "your_app_password",
            "recipient":  "admin@example.com",
        }
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            cfg.write(f)
        print(f"[Alerter] Created template config → {CONFIG_PATH}")
        print("[Alerter] Edit config.ini to set your Telegram bot token & chat ID.")


def _send_telegram(message: str, bot_token: str, chat_id: str):
    try:
        import requests
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id":    chat_id,
            "text":       message,
            "parse_mode": "HTML",
        }
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200:
            print("[Alerter] ✅ Telegram alert sent.")
        else:
            print(f"[Alerter] ⚠️  Telegram returned {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[Alerter] Telegram error: {e}")


def _send_email(subject: str, body: str, cfg: configparser.SectionProxy):
    try:
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"]    = cfg["sender"]
        msg["To"]      = cfg["recipient"]

        with smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port", "587"))) as server:
            server.starttls()
            server.login(cfg["sender"], cfg["password"])
            server.send_message(msg)
        print("[Alerter] ✅ Email alert sent.")
    except Exception as e:
        print(f"[Alerter] Email error: {e}")


_alert_queue = []
_MAX_QUEUE   = 100


def _dedup_key(log_text: str) -> str:
    import hashlib
    return hashlib.md5(log_text.encode()).hexdigest()


def send_alert(log_text: str, severity: str, severity_lvl: int,
               anomaly_score: float = None, async_send: bool = True):
    _ensure_config()
    cfg = _load_config()

    min_level = int(cfg.get("telegram", "min_level", fallback=str(_DEFAULT_MIN_LEVEL)))
    if severity_lvl < min_level:
        return

    key = _dedup_key(log_text)
    if key in _alert_queue:
        return
    _alert_queue.append(key)
    if len(_alert_queue) > _MAX_QUEUE:
        _alert_queue.pop(0)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ml_note = ""
    if anomaly_score is not None:
        risk = "⚠️ ANOMALY" if anomaly_score < 0 else "Normal"
        ml_note = f"\n🤖 ML Score: {anomaly_score:.4f} ({risk})"

    message = (
        f"🚨 <b>SecureLog Alert</b>\n"
        f"──────────────────────\n"
        f"🕐 Time: <code>{now}</code>\n"
        f"🔖 Severity: <b>{severity}</b>\n"
        f"📋 Event: <code>{log_text[:300]}</code>"
        f"{ml_note}"
    )

    if async_send:
        t = threading.Thread(target=_dispatch, args=(message, cfg), daemon=True)
        t.start()
    else:
        _dispatch(message, cfg)


def _dispatch(message: str, cfg: configparser.ConfigParser):
    tg = cfg["telegram"] if "telegram" in cfg else {}
    if tg.get("enabled", "false").lower() == "true":
        token   = tg.get("bot_token", "")
        chat_id = tg.get("chat_id", "")
        if token and token != "YOUR_BOT_TOKEN_HERE":
            _send_telegram(message, token, chat_id)
        else:
            print("[Alerter] Telegram enabled but token not set in config.ini")
    else:
        print(f"[Alerter] (Telegram disabled) Would have sent: {message[:80]}…")

    em = cfg["email"] if "email" in cfg else {}
    if em.get("enabled", "false").lower() == "true":
        plain = message.replace("<b>", "").replace("</b>", "").replace("<code>", "").replace("</code>", "")
        _send_email(
            subject=f"[SecureLog] Security Alert",
            body=plain,
            cfg=em,
        )


if __name__ == "__main__":
    _ensure_config()
    print("[Alerter] Sending TEST alert (async=False) …")
    send_alert(
        log_text      = "TEST: DDoS traffic spike from 1.2.3.4",
        severity      = "🔴 Critical",
        severity_lvl  = 4,
        anomaly_score = -0.234,
        async_send    = False,
    )
    print("[Alerter] Done. Check your Telegram / email (if configured).")
