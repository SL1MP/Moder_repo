#!/usr/bin/env bash
# Точка входа для api / worker / beat.
# Миграции Alembic применяются здесь: контейнер api стартует после healthy db и redis.
set -euo pipefail

ROLE="${1:-api}"

wait_for() {
  local host="$1" port="$2" name="$3" attempts="${4:-60}"
  for i in $(seq 1 "$attempts"); do
    if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      echo "[entrypoint] ${name} доступен (${host}:${port})"
      return 0
    fi
    sleep 1
  done
  echo "[entrypoint] ${name} недоступен: ${host}:${port}" >&2
  return 1
}

wait_for "${POSTGRES_HOST:-db}" "${POSTGRES_PORT:-5432}" "PostgreSQL"

case "$ROLE" in
  api)
    echo "[entrypoint] применяю миграции Alembic"
    alembic upgrade head
    exec uvicorn app.main:app \
      --host 0.0.0.0 --port "${API_PORT:-8000}" \
      --proxy-headers --forwarded-allow-ips='*' \
      ${UVICORN_EXTRA_ARGS:-}
    ;;
  worker)
    exec celery -A app.tasks.celery_app.celery_app worker \
      --loglevel="${CELERY_LOG_LEVEL:-INFO}" \
      --queues="${CELERY_QUEUES:-moderation,maintenance}" \
      --concurrency="${CELERY_CONCURRENCY:-4}"
    ;;
  beat)
    exec celery -A app.tasks.celery_app.celery_app beat \
      --loglevel="${CELERY_LOG_LEVEL:-INFO}"
    ;;
  migrate)
    exec alembic upgrade head
    ;;
  bootstrap)
    alembic upgrade head
    exec python -m app.cli bootstrap "${@:2}"
    ;;
  cli)
    exec python -m app.cli "${@:2}"
    ;;
  *)
    exec "$@"
    ;;
esac
