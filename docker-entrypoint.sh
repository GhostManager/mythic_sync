#!/bin/sh
set -eu

redis_hostname="${REDIS_HOSTNAME:-127.0.0.1}"
redis_url="${REDIS_URL:-}"

if [ -z "$redis_url" ] && { [ "$redis_hostname" = "127.0.0.1" ] || [ "$redis_hostname" = "localhost" ]; }; then
    redis-server --appendonly yes --appendfsync always --dir /data --daemonize yes

    /opt/venv/bin/python -u /app/sync.py &
    app_pid=$!

    shutdown() {
        trap - TERM INT
        kill -TERM "$app_pid" 2>/dev/null || true
        redis-cli -h 127.0.0.1 shutdown save 2>/dev/null || true
    }

    trap shutdown TERM INT
    set +e
    wait "$app_pid"
    app_status=$?
    set -e
    redis-cli -h 127.0.0.1 shutdown save 2>/dev/null || true
    exit "$app_status"
fi

exec /opt/venv/bin/python -u /app/sync.py
