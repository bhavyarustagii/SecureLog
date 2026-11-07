FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        tshark \
        libpcap-dev \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN usermod -aG wireshark root 2>/dev/null || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir \
        scikit-learn \
        requests \
        streamlit-authenticator

COPY . .

RUN mkdir -p /data && ln -s /data/securelog.db /app/securelog.db 2>/dev/null || true

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "dashboard_advanced.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
