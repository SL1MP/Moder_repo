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

### Отчёты по существующей заявке: `moderation scan`

REST API создания заявок на Go ещё не перенесён — заявки заводит python-версия,
а отчёты о сканировании умеет делать только Go. Команда `scan` закрывает этот
разрыв: берёт УЖЕ СУЩЕСТВУЮЩИЙ пакет заявки, прогоняет по нему сканеры
содержимого и пишет отчёты.

```bash
docker compose exec api-go moderation scan --item 108
```

`--item` — это `request_item.id`, он виден в адресе карточки пакета и в ответе
`GET /api/v1/requests/{id}`.

Что команда делает:

- берёт артефакт из карантинной зоны, а если он уже вычищен после публикации —
  скачивает заново из реестра тем же шагом, что и конвейер;
- прогоняет `banner_scan` (YARA) и `sast_scan` (semgrep);
- пишет файлы отчётов, строку `scan_report` и находки `code_finding`.

Чего команда НАМЕРЕННО не делает: не меняет статус заявки и не пишет строки
`pipeline_step`. Ими владеет python-конвейер, и вмешательство второго процесса
в его состояние дало бы расхождение, которое потом ищут днями.

После прогона отчёты доступны там же, где и всегда:

```
https://<хост>/api/v1/request-items/108/reports
https://<хост>/api/v1/request-items/108/reports/banner_scan.html
```

### Запуск в общем стеке (рекомендуемый способ)

Сервис заведён в `docker-compose.yml` как `api-go` и доступен по тому же
адресу, что и приложение: nginx отдаёт ему префикс `/api/v1/request-items/`,
остальной `/api/` по-прежнему уходит на python-сервис. Конфликта нет —
маршрута `/api/v1/request-items` в python-версии не существует, поэтому
ссылки `json_url` и `html_url` из отчётов работают как есть.

```bash
# один раз: миграции 0005-0007 на уже существующую базу Alembic
docker compose exec -T db psql -U moderation -d moderation < backend-go/migrations/0005_scan_reports.up.sql
docker compose exec -T db psql -U moderation -d moderation < backend-go/migrations/0006_artifact_uniqueness.up.sql
docker compose exec -T db psql -U moderation -d moderation < backend-go/migrations/0007_dry_run_status.up.sql

# собрать и поднять
docker compose up -d --build api-go
docker compose up -d --build nginx
```

Проверка:

```bash
curl https://<ваш-хост>/api/v1/request-items/1/reports
# {"reports":[],"request_item_id":1}
```

Порт наружу у `api-go` намеренно не публикуется: у сервиса нет собственной
аутентификации, и доступ к нему идёт только через nginx. Миграции сервис не
применяет сам — в базе уже работает Alembic python-версии, и второй
автоматический мигратор поверх неё создал бы трудноотлаживаемую гонку.

### Как запустить сервис отдельно (для разработки)

Ниже — полный порядок для машины, где УЖЕ работает Python-стек (обычный случай:
база создана Alembic'ом, порты 8000/5432/9000 заняты). Останавливать Python не
нужно, Go-сервис работает с той же базой и тем же хранилищем.

**1. Go на машине.** Нужен 1.25 или новее (`go.mod`: `go 1.25.0`).

```bash
go version
```

Если Go нет — ставить не обязательно: бинарник собирается статически и
переносится копированием с любой машины с Go.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o moderation ./cmd/moderation
scp moderation user@host:~/
```

Получается ~20 МБ, `statically linked`, без единой внешней библиотеки.

**2. Сборка.**

```bash
cd backend-go
go build ./cmd/moderation
```

**3. Миграции.** В боевой базе уже есть `0001`–`0004` (их накатил Alembic),
нужны только три новых. Они аддитивные: новая таблица `scan_report`,
ограничение уникальности на `artifact`, расширение `CHECK` для статуса
`dry_run`. Python-версии не мешают.

```bash
for f in migrations/000[567]*.up.sql; do
  psql 'postgres://moderation:ПАРОЛЬ@127.0.0.1:5432/moderation' -v ON_ERROR_STOP=1 -f "$f"
done
```

`0006` перед созданием ограничения удаляет дубли в `artifact` по паре
(версия, имя файла), оставляя самую раннюю строку. Посмотреть заранее, есть ли
они вообще:

```sql
SELECT package_version_id, filename, count(*)
FROM artifact GROUP BY 1,2 HAVING count(*) > 1;
```

**4. Запуск.** Значения берутся из `.env` Python-стека; внутридокерные имена
(`db`, `minio`) заменяются на `127.0.0.1`.

```bash
DATABASE_URL='postgres://moderation:ПАРОЛЬ@127.0.0.1:5432/moderation' \
LISTEN_ADDR='127.0.0.1:8010' \
S3_ENDPOINT='http://127.0.0.1:9000' \
S3_BUCKET='packages' \
S3_ACCESS_KEY='minioadmin' \
S3_SECRET_KEY='minioadmin' \
./moderation
```

Обязателен только `DATABASE_URL`. Остальное — значения по умолчанию
(`LISTEN_ADDR` = `:8000`, `S3_BUCKET` = `moderation-artifacts`,
`S3_REGION` = `us-east-1`).

Почему именно так:

- **`127.0.0.1`, а не `localhost`** — `localhost` может резолвиться сначала в
  `::1`, и если Docker опубликовал порт только на IPv4, подключение упадёт с
  «connection refused», что выглядит как «база недоступна».
- **`LISTEN_ADDR='127.0.0.1:8010'`, а не `:8010`** — у сервиса НЕТ
  аутентификации, а отчёты содержат выдержки из проверяемых пакетов. На
  машине, смотрящей в интернет, слушать на всех интерфейсах нельзя. Порт
  8010, потому что 8000 занят контейнером `api`.
- **Без `S3_ENDPOINT`** сервис поднимется, но маршруты отчётов не подключатся
  (в логе `WARN`, запрос к ним даст 404). Падать на старте из-за недоступного
  хранилища нельзя — `health` должен отвечать.

**5. Проверка.**

```bash
curl http://127.0.0.1:8010/health        # ok
curl http://127.0.0.1:8010/health/db     # ok — реальный ping базы
curl http://127.0.0.1:8010/metrics       # формат Prometheus
curl http://127.0.0.1:8010/api/v1/request-items/1/reports
```

Последний вернёт `{"reports":[],"request_item_id":1}` — маршрут подключён.

В логе при старте должно быть `хранилище отчётов подключено`. Если там
`S3_ENDPOINT не задан` — переменные не доехали.

**6. Доступ с рабочей машины** — пробросом порта, а не открытием наружу:

```bash
ssh -L 8010:127.0.0.1:8010 user@host
# дальше в браузере: http://localhost:8010/health
```

**7. Чтобы пережило выход из SSH** — `tmux`, `nohup ... &` или systemd-юнит.

#### Что вы увидите на самом деле

Список отчётов вернёт пустой массив и останется пустым. Отчёты создаёт
конвейер, а запустить его через Go пока нечем: REST API создания заявок не
перенесён, а заявки Python-версии отчётов не порождают.

То есть сейчас запуск Go-версии — это проверка, что она собирается, стартует,
видит базу и отдаёт свои эндпоинты. Чтобы увидеть отчёты на реальных пакетах,
нужен CLI-режим прогона конвейера по одному пакету либо перенос API заявок.

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
