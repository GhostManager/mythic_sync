FROM redis:7-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY sync.py docker-entrypoint.sh ./
RUN chmod +x /app/docker-entrypoint.sh

VOLUME ["/data"]

USER redis

ENTRYPOINT ["/app/docker-entrypoint.sh"]
