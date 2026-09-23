# syntax=docker/dockerfile:1
FROM nginx:alpine

# openssl нужен для самоподписанного сертификата, который entrypoint
# генерирует, если настоящий не положили (см. docker-entrypoint.d/10-tls.sh).
RUN apk add --no-cache openssl

# Конфиг зашит в образ, а не монтируется с хоста.
#
# Причина: bind-mount с хоста на Docker Desktop + WSL2 ломается — staging-путь
# под /run/desktop/mnt/host/wsl/docker-desktop-bind-mounts перестаёт
# резолвиться, и контейнер падает с "error mounting ... no such file or
# directory". Это происходит и с монтированием отдельного файла, и с
# монтированием каталога.
#
# Неизменяемый конфиг в образе — заодно правильная практика для прода: нет
# зависимости от файловой системы хоста. Правка конфига применяется так:
#   docker compose up -d --build nginx
# Файлы conf.d подключаются по алфавиту, отсюда числовые префиксы:
#   10 — сервер на 80, его кладёт entrypoint (отдаёт приложение или редиректит)
#   20 — сервер на 443
# Стоковый default.conf из образа удаляется: иначе его server на 80 стал бы
# конфликтующим default_server.
RUN rm -f /etc/nginx/conf.d/default.conf
COPY https.conf /etc/nginx/conf.d/20-https.conf
COPY snippets/ /etc/nginx/snippets/

# Каталог с сертификатами. В репозитории он пуст (только .gitkeep) — настоящие
# ключи сюда кладёт `make certs` и они не коммитятся. Копируется каталогом, а
# не файлами, именно поэтому: COPY на отсутствующий файл провалил бы сборку у
# всех, кто разворачивает без своего сертификата.
COPY certs/ /etc/nginx/certs/

COPY docker-entrypoint.d-10-tls.sh /docker-entrypoint.d/10-tls.sh
RUN chmod +x /docker-entrypoint.d/10-tls.sh

EXPOSE 80 443

# Проверка конфига на этапе сборки.
#
# Раньше её было не сделать: `upstream moderation_api { server api:8000; }`
# заставлял nginx резолвить хост при разборе конфига, а во время сборки его
# нет. Теперь блока upstream нет — go-версия адресуется через переменную с
# resolver'ом (snippets/api-go-proxy.conf), и разбор ничего не резолвит.
#
# Проверять обязательно здесь, а не только при старте: ошибка в конфиге роняет
# nginx целиком, и наружу это выглядит не как поломка одного маршрута, а как
# ERR_CONNECTION_REFUSED на всём сайте. Ровно так и случилось: в блок
# /api/v1/admin/osv-sync подключили общий сниппет и следом задали свой
# proxy_read_timeout — nginx не разрешает задавать директиву дважды в одном
# контексте и отказался стартовать. Сборка при этом прошла успешно.
#
# Проверяются оба режима: и редирект с 80 на HTTPS, и отдача приложения на 80 —
# какой из них окажется в контейнере, решает entrypoint по NGINX_FORCE_HTTPS,
# и проверять только один значило бы ловить ошибку в половине установок.
#
# Сертификат на время проверки — одноразовый: настоящий генерирует entrypoint
# при старте, а `nginx -t` требует, чтобы файл существовал. Создаётся и
# удаляется внутри одного RUN, чтобы в образ не попал.
RUN set -eu; \
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=build-check" \
        -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt \
        >/dev/null 2>&1; \
    for mode in http-redirect http-serve; do \
        cp "/etc/nginx/snippets/$mode.conf" /etc/nginx/conf.d/10-check.conf; \
        nginx -t; \
    done; \
    rm -f /etc/nginx/conf.d/10-check.conf \
          /etc/nginx/certs/server.key /etc/nginx/certs/server.crt
