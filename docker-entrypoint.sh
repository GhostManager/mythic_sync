#!/bin/sh
set -eu

redis_hostname="${REDIS_HOSTNAME:-127.0.0.1}"

if [ "$redis_hostname" = "127.0.0.1" ] || [ "$redis_hostname" = "localhost" ]; then
    redis-server --appendonly yes --dir /data --daemonize yes
fi

exec /opt/venv/bin/python -u /app/sync.py
