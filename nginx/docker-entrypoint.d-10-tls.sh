#!/bin/sh
# Готовит TLS до старта nginx. Официальный образ выполняет всё из
# /docker-entrypoint.d/ перед запуском.
set -eu

CERT_DIR=/etc/nginx/certs
CRT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"

# Сертификата нет — генерируем самоподписанный. HTTPS должен подниматься
# всегда: без secure context браузер не даёт SPA window.crypto.subtle, а на
# нём построен PKCE, и вход через SSO падает с
# "Cannot read properties of undefined (reading 'digest')".
if [ ! -s "$CRT" ] || [ ! -s "$KEY" ]; then
    CN="${TLS_COMMON_NAME:-localhost}"
    echo "[nginx] сертификат не найден, генерирую самоподписанный для CN=$CN"
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY" -out "$CRT" \
        -days 825 -subj "/CN=$CN" \
        -addext "subjectAltName=DNS:$CN" >/dev/null 2>&1
    chmod 400 "$KEY"
    chmod 444 "$CRT"
else
    echo "[nginx] использую сертификат из $CERT_DIR"
fi

# Что делает порт 80: отдаёт приложение или редиректит на HTTPS.
case "${NGINX_FORCE_HTTPS:-false}" in
    1|true|TRUE|yes|on)
        echo "[nginx] порт 80 редиректит на HTTPS"
        cp /etc/nginx/snippets/http-redirect.conf /etc/nginx/conf.d/10-http.conf
        ;;
    *)
        echo "[nginx] порт 80 отдаёт приложение (NGINX_FORCE_HTTPS=false)"
        cp /etc/nginx/snippets/http-serve.conf /etc/nginx/conf.d/10-http.conf
        ;;
esac
