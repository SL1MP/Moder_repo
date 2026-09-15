#!/usr/bin/env bash
# Ждёт готовности Nexus перед bootstrap.
#
# Nexus поднимается 1-3 минуты, а контейнер считается Up сразу — без ожидания
# bootstrap падал на создании репозиториев. Отдельный случай, который важно
# отличать: контейнера нет вовсе (стек не поднят). Раньше это выглядело как
# бесконечные «Could not connect to server» без объяснения.
set -euo pipefail

COMPOSE=${COMPOSE:-docker compose}
ATTEMPTS=${ATTEMPTS:-60}
INTERVAL=${INTERVAL:-5}

uses_local_nexus() {
    grep -qE '^ARTIFACT_BASE_URL=https?://nexus[:/]' .env 2>/dev/null
}

nexus_running() {
    $COMPOSE --profile nexus ps --services --status running 2>/dev/null | grep -qx nexus
}

if ! nexus_running; then
    if uses_local_nexus; then
        cat >&2 <<'MSG'
Контейнер nexus не запущен, а ARTIFACT_BASE_URL указывает именно на него —
ждать нечего. Сначала поднимите стек:

  docker compose -f docker-compose.yml -f docker-compose.override.yml \
                 -f docker-compose.tls.yml --profile sso --profile nexus \
                 up -d --build

и только потом `make bootstrap`.
MSG
        exit 1
    fi
    echo "Контейнер nexus не запущен — жду внешний артефактори из ARTIFACT_BASE_URL."
fi

echo "Жду готовности Nexus (до $((ATTEMPTS * INTERVAL)) с)…"

# Цикл выполняется внутри одного контейнера: имя `nexus` резолвится только в
# сети compose, а поднимать контейнер на каждую попытку — дорого.
if $COMPOSE run --rm -e ATTEMPTS="$ATTEMPTS" -e INTERVAL="$INTERVAL" \
    --entrypoint sh api -c '
        i=0
        while [ "$i" -lt "$ATTEMPTS" ]; do
            i=$((i + 1))
            if curl -fs -o /dev/null "$ARTIFACT_BASE_URL/service/rest/v1/status"; then
                echo "Nexus готов"
                exit 0
            fi
            if [ $((i % 6)) -eq 0 ]; then
                echo "  …ещё жду ($((i * INTERVAL)) с)"
            fi
            sleep "$INTERVAL"
        done
        exit 1
    '; then
    exit 0
fi

cat >&2 <<MSG
Nexus не ответил за $((ATTEMPTS * INTERVAL)) с. Что смотреть:

  docker compose --profile nexus ps nexus
  docker compose logs nexus --tail=50

Первый старт на слабой машине может занять дольше — тогда просто повторите
\`make bootstrap\`, данные не пострадают.
MSG
exit 1
