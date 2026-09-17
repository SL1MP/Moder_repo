# REST API

Базовый префикс — `/api/v1`. Интерактивная документация: `/api/docs` (Swagger) и `/api/redoc`.

## Аутентификация

Все эндпоинты, кроме `/api/v1/auth/config`, `/api/v1/auth/token`, `/health` и `/metrics`, требуют
`Authorization: Bearer <token>`.

Токен — либо OIDC-токен пользователя (Keycloak, Authorization Code + PKCE), либо токен сервисной
учётки:

```bash
# Сервисная учётка (только при LOCAL_AUTH_ENABLED=true)
TOKEN=$(curl -sS -X POST http://localhost:8080/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"ci-bot","password":"..."}' | jq -r .access_token)

# Сервисный клиент Keycloak (client_credentials)
TOKEN=$(curl -sS -X POST "$OIDC_ISSUER/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d client_id=moderation-ci \
  -d client_secret="$OIDC_CLIENT_SECRET" | jq -r .access_token)
```

Роль и автор пишутся в заявку из claims токена.

## Формат ошибок

Единый для всех эндпоинтов: машинный код + человеческое сообщение на русском.

```json
{
  "error": {
    "code": "invalid_format",
    "message": "«lodash@4.17.21» не соответствует формату pypi. Ожидается: name==version (например, requests==2.31.0)",
    "details": {"expected_format": "name==version"},
    "request_id": "7c0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b"
  }
}
```

Коды: `unauthorized`, `forbidden`, `not_found`, `validation_error`, `invalid_format`,
`unknown_manager`, `limit_exceeded`, `rate_limited`, `conflict`, `upstream_error`, `circuit_open`,
`configuration_error`, `internal_error`.

## Добавление пакетов

### Способ 1 — перечисление пакетов

```bash
curl -sS -X POST http://localhost:8080/api/v1/requests \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: ci-build-4211' \
  -d '{
        "manager": "pypi",
        "packages": [
          {"name": "requests", "version": "2.31.0"},
          {"name": "pydantic", "version": "2.6.4"}
        ],
        "reason": "Сервис выставления счетов, спринт 41"
      }'
```

Допустима краткая форма строкой — сервис разбирает по формату менеджера:

```bash
curl -sS -X POST http://localhost:8080/api/v1/requests \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"manager":"pypi","packages":["requests==2.31.0","pydantic==2.6.4"]}'
```

Форматы записей по менеджерам: `name==version` (pypi), `[@scope/]name@version` (npm),
`module@vX.Y.Z` (go), `Id@version` (nuget).

### Способ 2 — файл с зависимостями

```bash
curl -sS -X POST http://localhost:8080/api/v1/requests \
  -H "Authorization: Bearer $TOKEN" \
  -F manager=npm \
  -F file=@package-lock.json \
  -F include_transitive=false \
  -F 'reason=Перевод фронтенда на внутренний реестр'
```

Поддерживаемые файлы: `requirements*.txt`, `poetry.lock`, `pyproject.toml` (pypi);
`package-lock.json`, `yarn.lock`, `package.json` (npm); `go.mod`, `go.sum` (go);
`packages.lock.json`, `packages.config`, `*.csproj` (nuget).

Парсер различает прямые и транзитивные зависимости. При `include_transitive=false` (по умолчанию)
транзитивные в заявку не попадают, а в ответе приходит предупреждение:

> Проверяется и публикуется только сам заявленный пакет. Транзитивные зависимости автоматически не
> подтягиваются — если они нужны, заведите их отдельно.

### Способ 3 — файл из GitLab (только чтение)

Требует подключённого GitLab в профиле пользователя.

```bash
curl -sS -X POST http://localhost:8080/api/v1/gitlab/requests \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"project":"group/service","path":"requirements.txt","ref":"release/1.4","include_transitive":false}'
```

### Ответ (общий для всех способов)

`202 Accepted`. Конвейер запускается асинхронно.

```json
{
  "request_id": 42,
  "manager": "pypi",
  "status": "pending",
  "accepted": 1,
  "skipped_already_in_base": 1,
  "invalid": 1,
  "warnings": [],
  "packages": [
    {"raw": "pydantic 2.6.4", "state": "new", "name": "pydantic", "version": "2.6.4",
     "dependency_kind": "direct", "message": null},
    {"raw": "requests 2.31.0", "state": "already_in_base", "name": "requests", "version": "2.31.0",
     "package_version_id": 7, "status": "approved", "link": "/api/v1/packages/7",
     "install_command": "pip install -i http://nexus:8081/repository/pypi-internal/simple requests==2.31.0",
     "message": "requests 2.31.0 уже одобрен — заявка по нему не требуется."},
    {"raw": "lodash@4.17.21", "state": "invalid_format",
     "message": "«lodash@4.17.21» не соответствует формату pypi. Ожидается: name==version",
     "expected_format": "name==version"}
  ],
  "status_url": "/api/v1/requests/42"
}
```

Пометки по каждому пакету: `new` (принят к проверке), `already_in_base` (с ссылкой на запись и
командой установки — в заявку не попадает), `invalid_format` (с ожидаемым форматом).

### Идемпотентность

Заголовок `Idempotency-Key`: повтор с тем же ключом возвращает **ту же заявку** и код `200` вместо
`202`. Ключ уникален на весь сервис — используйте, например, `ci-<project>-<build-id>`.

### Лимиты

Из конфига: `MAX_UPLOAD_SIZE_BYTES` (размер файла, `413 limit_exceeded`),
`MAX_PACKAGES_PER_REQUEST` (число пакетов в заявке, `413`),
`RATE_LIMIT_REQUESTS_PER_MINUTE` (частота запросов на пользователя, `429 rate_limited`).

## Статус заявки

```bash
curl -sS http://localhost:8080/api/v1/requests/42 -H "Authorization: Bearer $TOKEN"
```

Ответ — агрегат плюс по каждому пакету: текущий шаг, результат, причина и что делать дальше.

```json
{
  "request_id": 42,
  "status": "awaiting_security",
  "status_title": "Ждёт DevSecOps",
  "approved": false,
  "summary": {"total": 1, "approved": 0, "awaiting_security": 1, "awaiting_legal": 0,
              "quarantined": 0, "rejected": 0, "failed": 0, "by_status": {"awaiting_security": 1}},
  "packages": [{
    "id": 91,
    "name": "vulnpkg", "version": "1.0.0",
    "status": "awaiting_security", "status_title": "Ждёт DevSecOps",
    "current_step": "vuln_scan", "current_step_title": "Проверка на уязвимости",
    "blocked_reason": "Найдены уязвимости с баллом выше порога 80: CVE-2024-0001 (98). Решение вынесено по снапшоту OSV osv-2024-05-20.",
    "next_action": "Возьмите версию с исправлением 2.0.0 либо дождитесь решения DevSecOps.",
    "license_spdx": "MIT",
    "max_vuln_score": 98.0,
    "vulnerabilities": [{"id": "CVE-2024-0001", "score": 98.0,
                         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                         "fixed_versions": ["2.0.0"], "url": "https://osv.dev/vulnerability/CVE-2024-0001"}],
    "steps": [
      {"code": "db_check", "order": 0, "title": "Проверка наличия в базе", "result": "pass", "message": "..."},
      {"code": "blacklist", "order": 1, "title": "Blacklist", "result": "pass", "message": "..."},
      {"code": "quarantine", "order": 2, "title": "Карантин", "result": "pass", "message": "..."},
      {"code": "license", "order": 3, "title": "Лицензия", "result": "pass", "message": "..."},
      {"code": "download", "order": 4, "title": "Скачивание артефакта", "result": "pass", "message": "..."},
      {"code": "vuln_scan", "order": 5, "title": "Проверка на уязвимости", "result": "fail", "message": "..."},
      {"code": "publish", "order": 6, "title": "Выгрузка в артефактори", "result": "skipped",
       "message": "Не выполнялся: конвейер остановлен на шаге «Проверка на уязвимости»."}
    ]
  }]
}
```

### Блокирующий вариант для CI

```bash
#!/usr/bin/env bash
set -euo pipefail

RESP=$(curl -sS -X POST "$MODERATION_URL/api/v1/requests" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H "Idempotency-Key: ci-$CI_PROJECT_PATH_SLUG-$CI_PIPELINE_ID" \
  -d "{\"manager\":\"pypi\",\"packages\":$(jq -Rn --rawfile f requirements.txt '$f|split("\n")|map(select(length>0))'),\"reason\":\"$CI_PROJECT_PATH pipeline $CI_PIPELINE_ID\"}")

REQUEST_ID=$(jq -r .request_id <<<"$RESP")
FINAL=$(curl -sS "$MODERATION_URL/api/v1/requests/$REQUEST_ID?wait=true&timeout=600" \
  -H "Authorization: Bearer $TOKEN")

jq -r '.packages[] | "\(.status_title)\t\(.name) \(.version)\t\(.next_action // "")"' <<<"$FINAL"

# Ненулевой exit-code формирует клиент по полю approved
[ "$(jq -r .approved <<<"$FINAL")" = "true" ] || { echo 'Модерация не пройдена'; exit 1; }
```

`wait=true&timeout=<сек>` (1..1800) ждёт финального статуса. Если время вышло, возвращается текущее
состояние — `approved` при этом `false`.

## Остальные эндпоинты

### Заявки и пакеты

| Метод | Путь | Роль | Назначение |
| --- | --- | --- | --- |
| `GET` | `/requests?mine=true&status=&manager=` | любая | список заявок (developer видит свои) |
| `POST` | `/requests/{id}/retry` | автор, devsecops, admin | перезапуск пакетов со статусом `failed` |
| `POST` | `/requests/{id}/cancel` | автор, admin | закрыть заявку: пакеты больше не нужны (статус `cancelled`) |
| `GET` | `/packages?q=&manager=&version=&status=` | любая | поиск по базе пакетов |
| `GET` | `/packages/{version_id}` | любая | карточка версии: шаги, CVE, артефакты, команда установки |
| `POST` | `/packages/check` | любая | проверка наличия в базе без создания заявки |
| `POST` | `/packages/{version_id}/revoke` | devsecops | отзыв пакета (снятие с публикации) |
| `GET` | `/managers`, `/managers/detect?filename=` | любая | форматы записей и определение менеджера по файлу |
| `GET` | `/licenses` | любая | справочник SPDX для автодополнения |

Если действие отвечает «Схема базы не соответствует версии сервиса», дело не в заявке: в базе
не накатили миграцию. Что именно — покажет `docker compose run --rm api-go schema`.

Закрытие заявки (`cancel`) — отказ **автора**, а не решение роли: `rejected` значит «нельзя»,
`cancelled` — «уже не нужно», и путать их в отчётности нельзя. Закрываются только
незавершённые пакеты; одобренный, отклонённый или отозванный не трогается (опубликованный
снимает DevSecOps через `revoke`). Повторный вызов отвечает `409` («Заявка уже закрыта»), а
заявка, где закрывать нечего, — `409` с объяснением. Ответ — та же карточка заявки плюс поле
`cancelled` с числом закрытых пакетов.

```bash
# Закрыть свою заявку
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://moderation.example.com/api/v1/requests/42/cancel

# Проверка по базе
curl -sS -X POST http://localhost:8080/api/v1/packages/check \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"manager":"npm","packages":["lodash@4.17.21","left-pad@1.3.0"]}'
```

Поле `state` отвечает на вопрос «можно ли уже ставить», а не «есть ли строка в
базе» — запись создаётся в момент заведения заявки, задолго до её одобрения:

| `state` | Что значит | Что делать |
| --- | --- | --- |
| `approved` | одобрен и опубликован | ставить командой из `install_command` |
| `in_progress` | заявка уже есть, идёт модерация (`request_id`, `current_step`, `next_action`) | дождаться; повторную заявку не заводить |
| `blocked` | проверку не прошёл: `rejected`, `blacklisted`, `revoked`, `failed` (причина в `status_reason`) | подобрать другую версию или замену |
| `not_found` | в базе нет | заводить заявку |
| `invalid_format` | запись не соответствует формату менеджера (`expected_format`) | исправить запись |

Внутренний статус версии остаётся в поле `status` (`new`, `checking`,
`quarantined`, `awaiting_legal`, `awaiting_security`, `approved`, …) — он нужен для
диагностики, а решение принимается по `state`.

### Очереди и решения

| Метод | Путь | Роль |
| --- | --- | --- |
| `GET` | `/queue/security` | devsecops |
| `GET` | `/queue/legal` | legal |
| `GET` | `/queue/counters` | любая |
| `POST` | `/items/{id}/quarantine/release` | devsecops |
| `POST` | `/items/{id}/security-decision` | devsecops |
| `POST` | `/items/{id}/license-claim` | автор заявки, legal, devsecops, admin |
| `GET` | `/license-claims?status=pending` | legal, devsecops, admin (или свои) |
| `POST` | `/license-claims/{id}/decision` | legal |

```bash
# DevSecOps разрешает публикацию несмотря на CVE (конвейер возобновится с шага 4)
curl -sS -X POST http://localhost:8080/api/v1/items/91/security-decision \
  -H "Authorization: Bearer $SEC_TOKEN" -H 'Content-Type: application/json' \
  -d '{"approve":true,"comment":"Уязвимый код не используется, компенсирующая мера — WAF"}'

# Разработчик заявляет лицензию (сервис проверит доступность ссылки и сохранит снапшот текста)
curl -sS -X POST http://localhost:8080/api/v1/items/92/license-claim \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com/org/repo/raw/main/LICENSE","spdx_id":"MIT","comment":"Файл в корне"}'

# Юрист подтверждает (конвейер возобновится с шага 4)
curl -sS -X POST http://localhost:8080/api/v1/license-claims/5/decision \
  -H "Authorization: Bearer $LEGAL_TOKEN" -H 'Content-Type: application/json' \
  -d '{"approve":true,"comment":"MIT согласована"}'
```

При отклонении (`approve:false`) комментарий обязателен — иначе `422 validation_error`.

### Обсуждения и уведомления

| Метод | Путь | Назначение |
| --- | --- | --- |
| `GET` | `/requests/{id}/comments?request_item_id=` | ветка заявки или конкретного пакета |
| `POST` | `/requests/{id}/comments` | сообщение (markdown, упоминания `@логин`) |
| `PATCH`/`DELETE` | `/comments/{id}` | правка/удаление своего сообщения |
| `GET` | `/notifications?only_unread=true` | непрочитанные события |
| `POST` | `/notifications/read` | `{"ids": [...]}` или `{"all": true}` |

Правка позже `COMMENT_EDIT_WINDOW_MINUTES` ставит пометку «изменено»; удаление — «удалено». И то и
другое пишется в аудит-лог.

### Настройки и администрирование

| Метод | Путь | Роль | Назначение |
| --- | --- | --- | --- |
| `GET` | `/settings` | любая | действующие значения с именами переменных (только чтение) |
| `GET` | `/settings/policies` | любая | blacklist, справочник лицензий, состояние снапшота OSV |
| `POST` | `/admin/reload` | admin | перечитать `blacklist.yml` и `licenses.yml` |
| `GET` | `/admin/audit?action=&entity_type=&actor=` | admin | аудит-лог |
| `GET` | `/admin/osv-versions` | devsecops | загруженные версии снапшота |
| `POST` | `/admin/osv-sync?force=true` | devsecops | запустить синхронизацию снапшота |
| `GET` | `/system/status` | любая | жив ли worker, сколько пакетов зависло в очереди |
| `POST` | `/admin/queue-sweep` | admin | немедленно разобрать зависшие пакеты |

`GET /system/status`:

```json
{
  "worker": {
    "alive": false,
    "detail": "worker молчит 312 с — очередь никто не разбирает",
    "last_seen": "2026-08-14T09:12:04Z",
    "age_seconds": 312.4
  },
  "watchdog": { "enabled": true, "interval_seconds": 30, "stuck_after_seconds": 120 },
  "queue": { "stuck_items": 2, "stuck_item_ids": [17, 18] }
}
```

Эндпоинтов записи настроек нет: конфигурация меняется только правкой `.env` и рестартом.

### GitLab

| Метод | Путь | Назначение |
| --- | --- | --- |
| `GET` | `/gitlab/status` | состояние подключения |
| `GET` | `/gitlab/authorize` | ссылка OAuth (scope `read_api read_repository`) |
| `GET` | `/gitlab/callback?code=` | обмен кода на токены (шифруются Fernet) |
| `DELETE` | `/gitlab/connection` | отключить |
| `POST` | `/gitlab/requests` | заявка по файлу из приватного проекта |

Токены GitLab никогда не возвращаются в API.

### Служебные

| Путь | Назначение |
| --- | --- |
| `GET /health` | живость, связность с БД и наличие живого worker'а (`checks.worker`) |
| `GET /metrics` | метрики Prometheus |
| `GET /api/v1/auth/config` | параметры OIDC для SPA |
| `GET /api/v1/auth/me` | текущий пользователь и его роли |
