#!/usr/bin/env bash
set -e

# Optional: start Cloud SQL Proxy if CLOUDSQL_INSTANCE is set
if [[ -n "${CLOUDSQL_INSTANCE}" ]]; then
  echo "[ENTRYPOINT] Starting Cloud SQL Proxy for instance: ${CLOUDSQL_INSTANCE}"
  cloud-sql-proxy "${CLOUDSQL_INSTANCE}" \
    --address 0.0.0.0 \
    --port "${DB_PORT:-5432}" \
    >/var/log/cloud-sql-proxy.log 2>&1 &

  # Wait for Postgres to be reachable
  echo "[ENTRYPOINT] Waiting for Postgres to become ready on ${DB_HOST:-127.0.0.1}:${DB_PORT:-5432}..."
  for i in {1..30}; do
    if pg_isready -h "${DB_HOST:-127.0.0.1}" -p "${DB_PORT:-5432}" >/dev/null 2>&1; then
      echo "[ENTRYPOINT] Postgres is ready."
      break
    fi
    sleep 1
  done
fi

# At this point:
# - Postgres is reachable via DB_HOST/DB_PORT (Cloud SQL via proxy or external)
# - You can rely on DATABASE_URL or DB_* envs in your server.py

echo "[ENTRYPOINT] Starting server: $*"
exec "$@"
