#!/usr/bin/env bash
# Проверяет, что realm «moderation» доступен, и подсказывает, что делать иначе.
# При профиле sso realm импортируется самим контейнером (--import-realm), поэтому
# скрипт только ждёт готовности и печатает адреса.
set -euo pipefail

ISSUER="${OIDC_PUBLIC_ISSUER:-${OIDC_ISSUER:-http://localhost:8081/realms/moderation}}"
ATTEMPTS="${ATTEMPTS:-60}"

echo "[keycloak] ожидаю ${ISSUER}/.well-known/openid-configuration"
for i in $(seq 1 "$ATTEMPTS"); do
  if curl -fsS "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo "[keycloak] realm доступен: ${ISSUER}"
    echo "[keycloak] группы: moderation-admin, moderation-devsecops, moderation-legal, moderation-developer"
    echo "[keycloak] сопоставление групп с ролями задаётся переменными ROLE_MAPPING_* в .env"
    exit 0
  fi
  sleep 2
done

cat >&2 <<'EOF'
[keycloak] realm недоступен.
  - Свой Keycloak: поднимите профиль sso — docker compose --profile sso up -d keycloak
  - Внешний Keycloak: импортируйте keycloak/realm-moderation.json вручную
    (Realm settings → Partial import) и укажите OIDC_ISSUER в .env
EOF
exit 1
