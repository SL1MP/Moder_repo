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
#   00 — upstream (объявлен до серверных блоков)
#   10 — сервер на 80, его кладёт entrypoint (отдаёт приложение или редиректит)
#   20 — сервер на 443
# Стоковый default.conf из образа удаляется: иначе его server на 80 стал бы
# конфликтующим default_server.
RUN rm -f /etc/nginx/conf.d/default.conf
COPY upstream.conf /etc/nginx/conf.d/00-upstream.conf
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

# Проверку `nginx -t` на этапе сборки делать нельзя: nginx резолвит хосты из
# upstream уже при разборе конфига, а хоста `api` во время build нет —
# получили бы "host not found in upstream". Конфиг проверяется при старте
# контейнера, когда docker-DNS уже отдаёт адрес api.
