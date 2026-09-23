#!/usr/bin/env bash
#
# Перенос .env со стенда на python-версии в вид, который читает go-версия.
#
# Зачем скриптом, а не руками: переменных около сотни, часть переименована, а
# часть перестала читаться. Пропущенное переименование не ломает запуск — оно
# тихо возвращает настройку к значению по умолчанию, и заметно это становится
# через сутки по расписанию, которое никто не менял. Руками такое пропускается
# на третьем десятке строк.
#
# Что делает:
#   * сохраняет ВАШИ значения — ничего не придумывает за вас;
#   * переименовывает изменившиеся настройки, перенося значение;
#   * убирает те, которые go-версия не читает, и говорит про каждую почему;
#   * дописывает новые с умолчаниями и помечает те, что надо заполнить.
#
# Исходный файл не трогается: результат пишется рядом, сверить можно diff'ом.
#
# Использование:
#   scripts/env-upgrade.sh [путь-к-старому-.env] [куда-писать]
#   по умолчанию: .env -> .env.new
#
# Дальше:
#   diff .env .env.new        # посмотреть, что изменилось
#   cp .env .env.backup       # на всякий случай
#   mv .env.new .env

set -euo pipefail

SRC="${1:-.env}"
DST="${2:-.env.new}"

if [[ ! -f "$SRC" ]]; then
    echo "Не найден исходный файл: $SRC" >&2
    echo "Использование: $0 [путь-к-старому-.env] [куда-писать]" >&2
    exit 1
fi
if [[ -e "$DST" ]]; then
    echo "Файл $DST уже существует — не перезаписываю." >&2
    echo "Удалите его или укажите другое имя: $0 $SRC другое-имя" >&2
    exit 1
fi

# ---------------------------------------------------------------- чтение
# Значения читаем сами, а не через `source`: в .env попадаются пароли со
# спецсимволами, и отдать их интерпретатору оболочки — способ получить либо
# синтаксическую ошибку, либо выполнение того, что в пароле записано.
declare -A OLD
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" != *=* ]] && continue
    key="${line%%=*}"
    val="${line#*=}"
    key="${key//[[:space:]]/}"
    # Хвостовой комментарий: только если перед # есть пробел — иначе решётка
    # внутри значения (она бывает в паролях) обрезала бы само значение.
    if [[ "$val" =~ [[:space:]]+#.*$ ]]; then
        val="${val%%[[:space:]]#*}"
    fi
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    OLD["$key"]="$val"
done < "$SRC"

# old_or — значение из старого файла, иначе умолчание.
old_or() { local k="$1" d="${2-}"; echo "${OLD[$k]:-$d}"; }
# has — была ли переменная задана и непуста.
has() { [[ -n "${OLD[$1]:-}" ]]; }

RENAMED=()
DROPPED=()
ADDED=()

# renamed — перенос значения под новым именем.
renamed() {
    local from="$1" to="$2"
    if has "$from"; then
        RENAMED+=("$from -> $to (значение ${OLD[$from]} сохранено)")
        echo "${OLD[$from]}"
    else
        echo "$3"
    fi
}

# ---------------------------------------------------------------- перенос
OSV_INTERVAL="$(old_or OSV_SYNC_INTERVAL_SECONDS 21600)"
OSV_CRON_NOTE=""
if has OSV_SYNC_CRON && ! has OSV_SYNC_INTERVAL_SECONDS; then
    # Cron в интервал в общем виде не переводится, а молча взять умолчание
    # (6 часов) значило бы поменять расписание, о котором не договаривались.
    # Суточный интервал — ближайший аналог самого частого случая «раз в ночь»;
    # решение всё равно за человеком, поэтому ставим метку.
    OSV_INTERVAL=86400
    OSV_CRON_NOTE="   # ❗ПРОВЕРИТЬ: было OSV_SYNC_CRON=${OLD[OSV_SYNC_CRON]}, поставлены сутки"
    RENAMED+=("OSV_SYNC_CRON -> OSV_SYNC_INTERVAL_SECONDS (расписание задаётся интервалом)")
fi

RETRY="$(renamed HTTP_RETRIES REGISTRY_RETRY_ATTEMPTS 3)"
BREAKER="$(renamed CIRCUIT_BREAKER_FAIL_MAX REGISTRY_BREAKER_THRESHOLD 5)"
BREAKER_OPEN="$(renamed CIRCUIT_BREAKER_RESET_SECONDS REGISTRY_BREAKER_OPEN_SECONDS 30)"
ORPHAN_TTL="$(renamed S3_ORPHAN_TTL_HOURS STAGING_ORPHAN_TTL_HOURS 24)"
CLEANUP="$(renamed S3_CLEANUP_INTERVAL_SECONDS STAGING_CLEANUP_INTERVAL_SECONDS 7200)"

for dead in \
    "S3_ENDPOINT|S3 из сервиса убран: временная зона и отчёты живут в артефактори" \
    "S3_BUCKET|то же" \
    "S3_ACCESS_KEY|то же" \
    "S3_SECRET_KEY|то же" \
    "S3_REGION|то же" \
    "S3_SECURE|то же" \
    "S3_VIRTUAL_HOST|то же" \
    "REDIS_URL|очередь в Postgres, брокер не нужен" \
    "CELERY_BROKER_URL|то же" \
    "CELERY_RESULT_BACKEND|то же" \
    "WORKER_HEARTBEAT_INTERVAL_SECONDS|отметка воркера жила в Redis; живость видна по очереди" \
    "WORKER_HEARTBEAT_TTL_SECONDS|то же" \
    "OSV_SOURCE|заменено на OSV_DB_SOURCE" \
    "OSV_API_URL|онлайнового запроса к osv.dev нет, проверка по снапшоту" \
    "OSV_SCANNER_BIN|внешний бинарь osv-scanner не используется" \
    "HTTP_TIMEOUT_SECONDS|таймаут клиента общий и задан в коде" \
    "API_PORT|python-api погашен" \
    "MINIO_PORT|MinIO удалён" \
    "MINIO_CONSOLE_PORT|MinIO удалён" \
    "MINIO_IMAGE|MinIO удалён" \
    "OIDC_CLIENT_SECRET|клиент публичный (Authorization Code + PKCE)" \
    "OIDC_AUDIENCE|aud не проверяется намеренно, см. internal/auth/jwt.go" \
    "ARTIFACT_PATH_TEMPLATE_PYPI|раскладку задаёт плагин менеджера, не настройка" \
    "ARTIFACT_PATH_TEMPLATE_NPM|то же" \
    "ARTIFACT_PATH_TEMPLATE_GO|то же" \
    "ARTIFACT_PATH_TEMPLATE_NUGET|то же" \
; do
    name="${dead%%|*}"; why="${dead#*|}"
    has "$name" && DROPPED+=("$name — $why")
done

for new in ARTIFACT_REPO_STAGING ARTIFACT_REPO_REPORTS SANDBOX_URL \
           ARTIFACT_REPO_MAVEN ARTIFACT_REPO_DOCKER ARTIFACT_REPO_CONAN \
           ARTIFACT_REPO_LUAROCKS ARTIFACT_REPO_TERRAFORM ARTIFACT_REPO_PHP \
           ARTIFACT_REPO_GIT ARTIFACT_REPO_FILES; do
    has "$new" || ADDED+=("$new")
done

mark() { has "$1" || echo "   # ❗ЗАПОЛНИТЬ"; }

# ---------------------------------------------------------------- запись
{
cat <<HEADER
# ============================================================================
# Конфигурация go-версии сервиса модерации.
# Перенесено из $SRC скриптом scripts/env-upgrade.sh $(date +%Y-%m-%d).
#
# Ваши значения сохранены. Строки с ❗ требуют решения.
# Что именно изменилось — в отчёте, который скрипт напечатал в консоль.
# ============================================================================

# --- общее ------------------------------------------------------------------
APP_ENV=$(old_or APP_ENV dev)
APP_NAME=$(old_or APP_NAME "Модерация пакетов")
LOG_LEVEL=$(old_or LOG_LEVEL INFO)
PUBLIC_BASE_URL=$(old_or PUBLIC_BASE_URL)
LISTEN_ADDR=$(old_or LISTEN_ADDR :8000)

# --- база данных ------------------------------------------------------------
POSTGRES_HOST=$(old_or POSTGRES_HOST db)
POSTGRES_PORT=$(old_or POSTGRES_PORT 5432)
POSTGRES_DB=$(old_or POSTGRES_DB moderation)
POSTGRES_USER=$(old_or POSTGRES_USER moderation)
POSTGRES_PASSWORD=$(old_or POSTGRES_PASSWORD)
# DSN подставляет docker-compose; заполните, если запускаете бинарник вне него.
DATABASE_URL=$(old_or DATABASE_URL)

# --- надёжность обработки очереди -------------------------------------------
PIPELINE_WATCHDOG_ENABLED=$(old_or PIPELINE_WATCHDOG_ENABLED true)
PIPELINE_WATCHDOG_INTERVAL_SECONDS=$(old_or PIPELINE_WATCHDOG_INTERVAL_SECONDS 30)
PIPELINE_STUCK_AFTER_SECONDS=$(old_or PIPELINE_STUCK_AFTER_SECONDS 120)

# --- политики модерации -----------------------------------------------------
QUARANTINE_DAYS=$(old_or QUARANTINE_DAYS 14)
VULN_MAX_SCORE=$(old_or VULN_MAX_SCORE 80)
BLACKLIST_FILE=$(old_or BLACKLIST_FILE /config/blacklist.yml)
ALLOWED_LICENSES_FILE=$(old_or ALLOWED_LICENSES_FILE /config/licenses.yml)

# --- песочница (новый шаг конвейера) ----------------------------------------
# Шаг включается сам, как только задан SANDBOX_URL. Без адреса он отдаёт pass
# с пометкой «выключен настройкой» — то есть проверки не происходит.
#
#   POST {SANDBOX_URL}/api/v1/scan/checkFile
#        ?file_name=<имя>&short_result=true&async_result=false&priority=3
#   X-API-Key: {SANDBOX_TOKEN}
#
# Вердикты: CLEAN -> pass; DANGEROUS -> fail; UNWANTED -> pass с пометкой;
# нет ответа -> warn и решение DevSecOps.
SANDBOX_URL=$(old_or SANDBOX_URL)$(mark SANDBOX_URL)
SANDBOX_TOKEN=$(old_or SANDBOX_TOKEN "$(old_or SEC_TOKEN)")$(mark SANDBOX_TOKEN)
SANDBOX_PRIORITY=$(old_or SANDBOX_PRIORITY 3)
SANDBOX_SHORT_RESULT=$(old_or SANDBOX_SHORT_RESULT true)
SANDBOX_TIMEOUT_SECONDS=$(old_or SANDBOX_TIMEOUT_SECONDS 900)
SANDBOX_INSECURE_TLS=$(old_or SANDBOX_INSECURE_TLS false)

# --- реестры пакетных менеджеров -------------------------------------------
REGISTRY_PYPI_URL=$(old_or REGISTRY_PYPI_URL https://pypi.org)
REGISTRY_NPM_URL=$(old_or REGISTRY_NPM_URL https://registry.npmjs.org)
REGISTRY_GO_PROXY=$(old_or REGISTRY_GO_PROXY https://proxy.golang.org)
REGISTRY_NUGET_URL=$(old_or REGISTRY_NUGET_URL https://api.nuget.org)
REGISTRY_MAVEN_URL=$(old_or REGISTRY_MAVEN_URL https://repo1.maven.org/maven2)
REGISTRY_MAVEN_SEARCH_URL=$(old_or REGISTRY_MAVEN_SEARCH_URL https://search.maven.org)
REGISTRY_DOCKER_URL=$(old_or REGISTRY_DOCKER_URL https://registry-1.docker.io)
REGISTRY_DOCKER_AUTH_URL=$(old_or REGISTRY_DOCKER_AUTH_URL https://auth.docker.io/token)
REGISTRY_DOCKER_SERVICE=$(old_or REGISTRY_DOCKER_SERVICE registry.docker.io)
REGISTRY_CONAN_URL=$(old_or REGISTRY_CONAN_URL https://center.conan.io)
REGISTRY_LUAROCKS_URL=$(old_or REGISTRY_LUAROCKS_URL https://luarocks.org)
REGISTRY_TERRAFORM_URL=$(old_or REGISTRY_TERRAFORM_URL https://registry.terraform.io)
REGISTRY_PACKAGIST_URL=$(old_or REGISTRY_PACKAGIST_URL https://repo.packagist.org)
GIT_BINARY=$(old_or GIT_BINARY git)
GIT_CLONE_TIMEOUT_SECONDS=$(old_or GIT_CLONE_TIMEOUT_SECONDS 600)

# --- повторы и предохранитель на вызовах к реестрам -------------------------
# Пришли на смену HTTP_RETRIES и CIRCUIT_BREAKER_*: повторяется отдельный
# запрос к реестру, а не весь прогон пакета целиком.
REGISTRY_RETRY_ATTEMPTS=$RETRY
REGISTRY_RETRY_BASE_DELAY_MS=$(old_or REGISTRY_RETRY_BASE_DELAY_MS 200)
REGISTRY_RETRY_MAX_DELAY_MS=$(old_or REGISTRY_RETRY_MAX_DELAY_MS 5000)
REGISTRY_BREAKER_THRESHOLD=$BREAKER
REGISTRY_BREAKER_OPEN_SECONDS=$BREAKER_OPEN

# --- сеть -------------------------------------------------------------------
HTTP_PROXY=$(old_or HTTP_PROXY)
HTTPS_PROXY=$(old_or HTTPS_PROXY)
NO_PROXY=$(old_or NO_PROXY "localhost,127.0.0.1,db,nexus,keycloak,api-go,web,nginx")

# --- артефактори ------------------------------------------------------------
# ВНИМАНИЕ при ARTIFACT_STORE=nexus: публикация реализована только для
# pypi, npm, nuget и go. Для остальных восьми менеджеров шаг публикации
# завершится ошибкой «не задан формат компонента Nexus» — уже ПОСЛЕ
# скачивания и всех проверок.
ARTIFACT_STORE=$(old_or ARTIFACT_STORE nexus)
ARTIFACT_BASE_URL=$(old_or ARTIFACT_BASE_URL)
ARTIFACT_USER=$(old_or ARTIFACT_USER)
ARTIFACT_TOKEN=$(old_or ARTIFACT_TOKEN)
ARTIFACT_AUTH_TYPE=$(old_or ARTIFACT_AUTH_TYPE basic)
ARTIFACT_DRY_RUN=$(old_or ARTIFACT_DRY_RUN false)

# Промежуточная зона и отчёты — НОВЫЕ репозитории, завести как RAW HOSTED.
# Промежуточная зона обязана отличаться от репозиториев менеджеров: иначе
# непроверенный пакет лежал бы там, откуда ставят разработчики. Сервис
# проверяет это на старте и отказывается подниматься.
ARTIFACT_REPO_STAGING=$(old_or ARTIFACT_REPO_STAGING moderation-staging)
ARTIFACT_REPO_REPORTS=$(old_or ARTIFACT_REPO_REPORTS moderation-reports)
ARTIFACT_REPO_OSV=$(old_or ARTIFACT_REPO_OSV osv-snapshots)

ARTIFACT_REPO_PYPI=$(old_or ARTIFACT_REPO_PYPI pypi-internal)
ARTIFACT_REPO_NPM=$(old_or ARTIFACT_REPO_NPM npm-internal)
ARTIFACT_REPO_GO=$(old_or ARTIFACT_REPO_GO go-internal)
ARTIFACT_REPO_NUGET=$(old_or ARTIFACT_REPO_NUGET nuget-internal)
ARTIFACT_REPO_MAVEN=$(old_or ARTIFACT_REPO_MAVEN maven-internal)
ARTIFACT_REPO_DOCKER=$(old_or ARTIFACT_REPO_DOCKER docker-internal)
ARTIFACT_REPO_CONAN=$(old_or ARTIFACT_REPO_CONAN conan-internal)
ARTIFACT_REPO_LUAROCKS=$(old_or ARTIFACT_REPO_LUAROCKS luarocks-internal)
ARTIFACT_REPO_TERRAFORM=$(old_or ARTIFACT_REPO_TERRAFORM terraform-internal)
ARTIFACT_REPO_PHP=$(old_or ARTIFACT_REPO_PHP php-internal)
ARTIFACT_REPO_GIT=$(old_or ARTIFACT_REPO_GIT git-internal)
ARTIFACT_REPO_FILES=$(old_or ARTIFACT_REPO_FILES files-internal)

# --- база уязвимостей OSV ---------------------------------------------------
# artifactory (умолчание) | http | file — разбор в docs/osv-snapshot.md
OSV_DB_SOURCE=$(old_or OSV_DB_SOURCE artifactory)
OSV_SNAPSHOT_PATH=$(old_or OSV_SNAPSHOT_PATH osv/latest/osv-all.zip)
OSV_LOCAL_DB_PATH=$(old_or OSV_LOCAL_DB_PATH /var/lib/osv-db)
OSV_MAX_STALENESS_DAYS=$(old_or OSV_MAX_STALENESS_DAYS 3)
OSV_DB_URL=$(old_or OSV_DB_URL)
OSV_DB_TOKEN=$(old_or OSV_DB_TOKEN)
OSV_DB_FILE=$(old_or OSV_DB_FILE)

# --- регламентные задачи worker-go ------------------------------------------
MAINTENANCE_ENABLED=$(old_or MAINTENANCE_ENABLED true)
QUARANTINE_SWEEP_INTERVAL_SECONDS=$(old_or QUARANTINE_SWEEP_INTERVAL_SECONDS 900)
STAGING_CLEANUP_INTERVAL_SECONDS=$CLEANUP
STAGING_ORPHAN_TTL_HOURS=$ORPHAN_TTL
OSV_SYNC_INTERVAL_SECONDS=$OSV_INTERVAL$OSV_CRON_NOTE

# --- наблюдатель сканирования -----------------------------------------------
SCAN_WATCHER_ENABLED=$(old_or SCAN_WATCHER_ENABLED true)
SCAN_WATCHER_INTERVAL_SECONDS=$(old_or SCAN_WATCHER_INTERVAL_SECONDS 60)
SCAN_WATCHER_BATCH=$(old_or SCAN_WATCHER_BATCH 10)
SCAN_WATCHER_ITEM_TIMEOUT_SECONDS=$(old_or SCAN_WATCHER_ITEM_TIMEOUT_SECONDS 1200)
SCAN_MAX_UNPACKED_BYTES=$(old_or SCAN_MAX_UNPACKED_BYTES 2147483648)
SCAN_MAX_FILES=$(old_or SCAN_MAX_FILES 20000)

# --- раскрытие транзитивных зависимостей ------------------------------------
RESOLVE_MAX_DEPTH=$(old_or RESOLVE_MAX_DEPTH 3)
RESOLVE_MAX_PACKAGES=$(old_or RESOLVE_MAX_PACKAGES 200)
RESOLVE_INCLUDE_OPTIONAL=$(old_or RESOLVE_INCLUDE_OPTIONAL false)
RESOLVE_CONCURRENCY=$(old_or RESOLVE_CONCURRENCY 8)

# --- доступ (OIDC / Keycloak) ----------------------------------------------
OIDC_ISSUER=$(old_or OIDC_ISSUER)
OIDC_PUBLIC_ISSUER=$(old_or OIDC_PUBLIC_ISSUER)
OIDC_CLIENT_ID=$(old_or OIDC_CLIENT_ID moderation-web)
ROLE_MAPPING_ADMIN=$(old_or ROLE_MAPPING_ADMIN moderation-admin)
ROLE_MAPPING_DEVSECOPS=$(old_or ROLE_MAPPING_DEVSECOPS moderation-devsecops)
ROLE_MAPPING_LEGAL=$(old_or ROLE_MAPPING_LEGAL moderation-legal)
ROLE_MAPPING_DEVELOPER=$(old_or ROLE_MAPPING_DEVELOPER moderation-developer)
LOCAL_AUTH_ENABLED=$(old_or LOCAL_AUTH_ENABLED false)
LOCAL_AUTH_SECRET=$(old_or LOCAL_AUTH_SECRET)
LOCAL_AUTH_TOKEN_TTL_MINUTES=$(old_or LOCAL_AUTH_TOKEN_TTL_MINUTES 480)

# --- GitLab (только чтение) -------------------------------------------------
GITLAB_URL=$(old_or GITLAB_URL)
GITLAB_OAUTH_CLIENT_ID=$(old_or GITLAB_OAUTH_CLIENT_ID)
GITLAB_OAUTH_CLIENT_SECRET=$(old_or GITLAB_OAUTH_CLIENT_SECRET)
GITLAB_OAUTH_REDIRECT_URI=$(old_or GITLAB_OAUTH_REDIRECT_URI)
FERNET_KEY=$(old_or FERNET_KEY)

# --- лимиты -----------------------------------------------------------------
MAX_UPLOAD_SIZE_BYTES=$(old_or MAX_UPLOAD_SIZE_BYTES 5242880)
MAX_PACKAGES_PER_REQUEST=$(old_or MAX_PACKAGES_PER_REQUEST 200)
MAX_ARTIFACT_SIZE_BYTES=$(old_or MAX_ARTIFACT_SIZE_BYTES 524288000)
COMMENT_EDIT_WINDOW_MINUTES=$(old_or COMMENT_EDIT_WINDOW_MINUTES 15)
# ❗ПРОВЕРИТЬ: go-версия РАНЬШЕ эту настройку игнорировала, теперь соблюдает —
# на обновлённом стенде ограничение заработает впервые. Интерфейс при загрузке
# дёргает несколько маршрутов сразу.
RATE_LIMIT_REQUESTS_PER_MINUTE=$(old_or RATE_LIMIT_REQUESTS_PER_MINUTE 30)

# --- снятые с конвейера шаги ------------------------------------------------
# banner_scan (YARA) и sast_scan (semgrep) сняты. Настройки оставлены: код
# сканеров цел, возврат шага в строй — миграция плюс строка в StepCodes.
BANNER_SCAN_ENABLED=false
SAST_ENABLED=false
SAST_MIN_SEVERITY=$(old_or SAST_MIN_SEVERITY medium)

# --- внешние контейнеры (compose) -------------------------------------------
NGINX_PORT=$(old_or NGINX_PORT 8080)
NGINX_TLS_PORT=$(old_or NGINX_TLS_PORT 8443)
NGINX_FORCE_HTTPS=$(old_or NGINX_FORCE_HTTPS false)
TLS_COMMON_NAME=$(old_or TLS_COMMON_NAME localhost)
KEYCLOAK_PORT=$(old_or KEYCLOAK_PORT 8081)
KEYCLOAK_TLS_PORT=$(old_or KEYCLOAK_TLS_PORT 9443)
NEXUS_PORT=$(old_or NEXUS_PORT 8082)
KEYCLOAK_ADMIN=$(old_or KEYCLOAK_ADMIN admin)
KEYCLOAK_ADMIN_PASSWORD=$(old_or KEYCLOAK_ADMIN_PASSWORD)
HEADER
} > "$DST"

chmod --reference="$SRC" "$DST" 2>/dev/null || chmod 600 "$DST"

# ---------------------------------------------------------------- отчёт
echo
echo "Готово: $SRC -> $DST"
echo

if ((${#RENAMED[@]})); then
    echo "Переименовано (значения перенесены):"
    printf '  %s\n' "${RENAMED[@]}"
    echo
fi
if ((${#DROPPED[@]})); then
    echo "Убрано — go-версия это не читает:"
    printf '  %s\n' "${DROPPED[@]}"
    echo
fi
if ((${#ADDED[@]})); then
    echo "Добавлено нового:"
    printf '  %s\n' "${ADDED[@]}"
    echo
fi

echo "Осталось сделать:"
grep -n "❗" "$DST" | sed 's/^/  /' || echo "  (помеченных строк нет)"
echo
echo "Дальше:"
echo "  diff $SRC $DST      # посмотреть глазами"
echo "  cp $SRC $SRC.backup"
echo "  mv $DST $SRC"
