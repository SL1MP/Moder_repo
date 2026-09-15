# backend-go

Go-версия backend'а сервиса модерации пакетов — план и обоснование переноса:
[`../docs/migration-to-go.md`](../docs/migration-to-go.md). Пока существует **параллельно** с
рабочим Python `../backend/`, не заменяет его — см. открытые вопросы в `migration-to-go.md`
насчёт судьбы Python-версии после переноса.


## Что готово сейчас

Конвейер перенесён целиком: все девять шагов, отчёты о сканировании и решения ролей.

| Пакет | Что делает |
|---|---|
| `internal/config` | `Load(getenv)`, все ошибки валидации разом |
| `internal/db`, `internal/repo` | pgx-пул и репозиторий без ORM |
| `internal/domain` | 17 структур домена, перечисления 1:1 с миграциями |
| `internal/registry` | плагины pypi / npm / go / nuget, нормализация SPDX |
| `internal/unpack` | безопасная распаковка артефакта (zip-slip, ссылки, архивные бомбы) |
| `internal/scanners` | YARA (баннеры) и semgrep (SAST) через внешние CLI |
| `internal/osv` | компараторы версий, диапазоны OSV, CVSS v3, локальный снапшот |
| `internal/artifactstore` | JFrog Artifactory и совместимые, режим dry-run |
| `internal/storage` | S3-совместимое хранилище (SigV4 на stdlib) + in-memory |
| `internal/reports` | отчёты о сканировании: JSON и самодостаточный HTML |
| `internal/pipeline` | девять шагов, блокировки, runner |
| `internal/decisions` | решения ролей с распространением на siblings |
| `internal/api` | health, metrics, выдача отчётов |

Не перенесено: разбор файлов зависимостей, REST API создания заявок, auth/OIDC, очередь
(NATS + Valkey вместо Celery), уведомления, watchdog. Шесть недостающих пакетных менеджеров —
обязательный скоуп, Docker первым (`../docs/ci-parity-gaps.md`).

### Как запускать тесты

Часть тестов — интеграционные, на реальном Postgres (принцип `../docs/testing.md`). Без
переменной они не падают, а честно пропускаются с указанием причины:

```bash
# юнит-часть — без базы
go test ./...

# целиком, с базой
createdb moderation_test
for f in migrations/*.up.sql; do psql -d moderation_test -v ON_ERROR_STOP=1 -f "$f"; done
MODERATION_TEST_POSTGRES_DSN='postgres://localhost/moderation_test' go test ./...
```

Тесты самодостаточны и идемпотентны: фикстуры namespace'ятся именем теста и сбрасываются
перед прогоном. Это не украшательство — без сброса тест, однажды доведший пакет до `approved`,
во второй раз останавливался бы на шаге 0 («версия уже одобрена») и «проходил», ничего не
проверив.

## История: фаза 1 (каркас)

Сделано и проверено (`go build ./...`, `go vet ./...`, `gofmt -l .` — чисто):

- `go.mod` — модуль `moderation`, `go 1.25.0` (совпало с sentrix само, тулчейн подтянулся
  автоматически при `go mod tidy`).
- `internal/config` — `Load(getenv)`, собирает все ошибки валидации разом (`errors.Join`),
  паттерн sentrix; проверено вручную — при одновременно невалидных `APP_ENV` и пустом
  `DATABASE_URL` возвращает обе ошибки в одном сообщении, не только первую.
- `internal/db` — `pgxpool`, без ORM (см. `docs/migration-to-go.md`: GORM у vumana — не
  повторять).
- `internal/api` — chi-роутер: `GET /health` (без БД), `GET /health/db` (пингует Postgres),
  `GET /metrics` (Prometheus).
- `cmd/moderation` — точка входа, graceful shutdown по SIGINT/SIGTERM.
- `migrations/0001`–`0004` — SQL-порт всех существующих Alembic-миграций (golang-migrate
  формат, `NNNN_name.up/down.sql`), включая явно сохранённый урок из `0004`
  (CHECK-ограничение `step_code` — источник истины миграция, не Go-константа; в проде уже
  ловился `CheckViolation` из-за расхождения).

**Проверено на реальном Postgres** (изолированный `docker compose -p modrepo-go-verify`, порт
55432, чтобы не задеть параллельно работающий стек `sentrix` на 5432 — снесён после проверки
вместе с volume): все четыре миграции применены `psql`-ом без ошибок, `\dt` показал все 16
таблиц, `\d pipeline_step` подтвердил, что CHECK `step_code` после `0004` включает
`banner_scan`/`sast_scan`. Собранный бинарник поднят против этой базы:
`GET /health` → `200 ok`, `GET /health/db` → `200 ok` (реальный `Ping`), `GET /metrics` отдаёт
Prometheus-формат, `SIGTERM` завершает сервер штатно (лог "получен сигнал остановки").

Не сделано: применение миграций пока только вручную через `psql` — отдельный compose-сервис
`migrate` (по образцу sentrix, `migrate/migrate` образ) ещё не заведён в `docker-compose.yml`
этого репозитория.

## Статус — фаза 2 (домен + репозиторий), в работе

Сделано и проверено на реальном Postgres (изолированный стек, снесён после проверки):

- `internal/domain` — `enums.go` (порт `backend/app/db/enums.py` 1:1) и `models.go` (порт
  `backend/app/db/models.py` — 16 структур, `User.HasRole`/`DisplayName` как методы).
- `internal/repo` — репозиторий поверх `pgx` без ORM: `package`/`package_version`/
  `moderation_request`/`request_item`/`pipeline_step` — Create/Get/List, включая
  `ListItemsByPackageVersion` — опору для `siblings_awaiting` (следующий шаг).
- `internal/repo/repo_test.go` — интеграционные тесты на реальном Postgres (пропускаются, если
  `MODERATION_TEST_POSTGRES_DSN` не задан — паттерн sentrix, не падают там, где БД нет):
  - `TestHappyPath_PyPI_AllStepsPass` — заявка → версия → 9 шагов конвейера pass → вторая
    заявка на ту же версию видна через `ListItemsByPackageVersion` (обе). **PASS**.
  - `TestIdempotencyKey_NoDuplicate` — повтор с тем же `Idempotency-Key` падает на
    UNIQUE-ограничении, не создаёт дубль. **PASS**.

Попутно исправлена находка code review в собственном коде: `GetModerationRequestByIdempotencyKey`
изначально сравнивал текст ошибки строкой вместо `errors.Is(err, pgx.ErrNoRows)` — нарушение
собственного правила из `docs/development-standards.md` ("sentinel-ошибки, не сравнение
строк"), исправлено сразу.

## Статус — фаза 2 продолжение: pipeline runner, шаги 0–3

Сделано и проверено на реальном Postgres (изолированный стек, снесён после проверки):

- `internal/pipeline` — `Step`/`StepOutcome`/`Context`, четыре шага
  (`db_check`/`blacklist`/`quarantine`/`license`), `Run()` — оркестратор с сохранением каждого
  шага в `pipeline_step` и точечным обновлением `request_item`/`package_version`.
  `BlacklistPolicy`/`LicensePolicy` — интерфейсы + `InMemory*`-реализации (целевая — БД, см.
  `docs/configuration-model.md`).
- Шаги 4–8 (download/vuln_scan/banner_scan/sast_scan/publish) **сознательно не заведены** —
  требуют ещё не перенесённых адаптеров (реестры пакетных менеджеров, `ArtifactStore`,
  `VulnerabilityIndex`, сканеры) — фазы 3 и 5. Не заглушены притворным `pass`.
- `internal/pipeline/runner_test.go` — 5 сценариев на реальном Postgres, все **PASS**:
  `TestDbCheck_TerminalBranches` (approved/blacklisted/revoked — терминально),
  `TestBlacklist_Rejects`, `TestQuarantine_HoldsRecentlyPublished` (с проверкой точного
  `QuarantineUntil`), `TestQuarantine_PassesOldEnough` (чистый прогон всех 4 шагов),
  `TestLicense_WarnDoesNotStopConveyor` — самый важный: подтверждает, что `license`-шаг **не**
  останавливает конвейер (`Stop=false`), в отличие от остальных, и что это корректно
  сохраняется и в `pipeline_step`, и в `request_item.status`/`current_step`.

**Не перенесено намеренно, требует отдельного решения:**
- Версионные диапазоны blacklist (`>=1.0,<2.0`) — только точное совпадение/`*` сейчас
  (`policy.go`, комментарий).
- Составные лицензионные выражения (`A OR B`) — только прямая проверка SPDX сейчас.
- Поведение `QuarantineStep` при отсутствующем `PublishedAt` — не сверено с Python-версией
  (там `published_at` заполняется плагином пакетного менеджера, которого здесь ещё нет).
- **Кросс-заявочное распространение решений (`siblings_awaiting`/`_apply_to_siblings`) и
  собственно обработчики решений ролей (`ReleaseQuarantine`/`DecideSecurity`/`DecideLicense`)
  — следующий шаг**, самый рискованный по потере поведения (см. `docs/architecture.md`).

**Дальше по `migration-to-go.md`, "Фазы"**: обработчики решений с sibling-propagation (используя
уже готовый `repo.ListItemsByPackageVersion` + `pipeline.Run(..., fromCode)` для резюмирования),
затем плагины пакетных менеджеров (фаза 3, с приоритетом Docker) и адаптеры (фаза 5, с Sandbox
как приоритетом наравне с Docker) — они разблокируют шаги 4–8.

## Запуск

```bash
cd backend-go
go build ./...
go vet ./...
gofmt -l .          # должно быть пусто

DATABASE_URL=postgres://moderation:moderation@localhost:5432/moderation APP_ENV=dev \
  go run ./cmd/moderation
```
