# syntax=docker/dockerfile:1

# --------------------------------------------------------------- realm
# Внешний адрес сервиса подставляется в realm на сборке, а не хардкодится в
# JSON: иначе файл в репозитории оказался бы привязан к одной машине и ломал
# бы локальную разработку. Адреса localhost остаются — оба сценария рабочие.
FROM alpine:3.20 AS realm
ARG PUBLIC_BASE_URL=http://localhost:8080
RUN apk add --no-cache jq
COPY realm-moderation.json /in.json
COPY realm-urls.jq /realm-urls.jq
# Проверка на выходе не формальность: пустой redirectUris означал бы, что
# подстановка сломалась, а Keycloak молча отклонял бы вход после логина.
RUN jq --arg url "${PUBLIC_BASE_URL%/}" -f /realm-urls.jq /in.json > /realm-moderation.json \
 && jq -e '.clients[] | select(.clientId == "moderation-web") | .redirectUris | length > 0' \
      /realm-moderation.json > /dev/null

# --------------------------------------------------------------- keycloak
FROM quay.io/keycloak/keycloak:25.0

# Realm зашит в образ, а не монтируется с хоста — по той же причине, что и
# конфиг nginx (см. nginx/Dockerfile): bind-mount с хоста на Docker Desktop +
# WSL2 ломается с "error mounting ... no such file or directory", потому что
# staging-путь под /run/desktop/mnt/host/wsl/docker-desktop-bind-mounts
# перестаёт резолвиться. С монтированием одного файла это случается особенно
# часто: путь пересоздаётся при каждой правке файла на хосте.
#
# Правка realm применяется так:
#   docker compose --profile sso up -d --build keycloak
#
# Файл кладём с правами на чтение для всех: Keycloak в официальном образе
# работает от uid 1000, а COPY по умолчанию делает владельцем root.
COPY --from=realm --chmod=444 /realm-moderation.json /opt/keycloak/data/import/realm-moderation.json

# Сертификаты для HTTPS. Каталог в репозитории пуст (только .gitkeep):
# настоящие ключи кладёт `make certs`, в git они не попадают. Владелец — uid
# 1000, иначе Keycloak не прочитает файлы и упадёт с "Key material not
# provided" (COPY по умолчанию делает владельцем root).
COPY --chown=1000:1000 certs/ /opt/keycloak/conf/certs/
