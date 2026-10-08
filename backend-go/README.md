# Backend Moderated Repository

`backend-go` — единственный backend сервиса. Он обслуживает HTTP API,
проверяет конфигурацию и схему БД, выполняет конвейер модерации и регламентные
задачи. Отдельного Python/FastAPI/Celery backend в проекте больше нет.

Python остаётся внутри runtime-образа только как зависимость отдельных
вспомогательных сканеров и генераторов; он не поднимает HTTP-сервис и не
участвует в очереди заявок.

## Состав

- `cmd/moderation` — единый бинарник API, worker, миграций и maintenance-команд;
- `internal/api` — REST API, OIDC/локальная аутентификация и авторизация;
- `internal/pipeline` — шаги модерации и возобновление после решений ролей;
- `internal/queue` — очередь в PostgreSQL с `LISTEN/NOTIFY` и атомарным захватом;
- `internal/registry` — менеджеры пакетов, загрузка и метаданные;
- `internal/artifactstore` — staging, публикация и удаление из Nexus;
- `internal/osv`, `internal/sandbox`, `internal/dragon` — внешние проверки;
- `internal/repo` — доступ к PostgreSQL;
- `migrations` — SQL-миграции текущей схемы.

## Конвейер

Текущая последовательность шагов:

1. `db_check`
2. `blacklist`
3. `quarantine`
4. `license`
5. `download`
6. `dragon_scan`
7. `vuln_scan`
8. `sandbox_scan`
9. `sbom`
10. `publish`

Применимость шага зависит от пакетного менеджера и настроек. Открытые
согласования юриста и DevSecOps могут существовать параллельно. Публикация
выполняется только после погашения всех блокирующих решений. OSV служит
предупреждением и сам по себе публикацию не блокирует.

## Запуск в Docker Compose

Проверить схему и применить миграции:

```bash
docker compose run --rm migrate-go schema
docker compose run --rm migrate-go
```

Собрать и запустить backend:

```bash
docker compose build api-go worker-go
docker compose up -d --no-deps --force-recreate api-go worker-go
```

API наружу отдаёт nginx. Напрямую порт `api-go` не публикуется.

## Локальная разработка

Требуется версия Go из `go.mod`.

```bash
cd backend-go
go test ./...
go run ./cmd/moderation api
```

Для worker:

```bash
cd backend-go
go run ./cmd/moderation worker
```

Конфигурация читается из переменных окружения и из web-настроек в БД.
Полный перечень параметров находится в корневом `.env.example` и в
`docs/configuration-model.md`.

## Диагностика

Проверка состояния схемы:

```bash
docker compose run --rm migrate-go schema
```

Диагностический запуск сканирования существующего элемента заявки:

```bash
docker compose exec worker-go moderation scan --item 108
```

Эта команда создаёт отчёты, но не заменяет штатный конвейер и не переводит
заявку между статусами.

Однократный разбор очереди без ожидания следующего цикла worker:

```bash
docker compose run --rm worker-go worker --once
```

Синхронизация снапшотов OSV:

```bash
docker compose run --rm worker-go maintenance --osv-sync --force
```

## Наблюдаемость

- `GET /health` — готовность API, БД и worker;
- `GET /metrics` — метрики Prometheus;
- `GET /api/v1/system/status` — состояние очереди и интеграций;
- JSON-логи содержат `request_id`, который nginx возвращает в
  `X-Request-Id`.

Детальное описание связей и потока данных: `docs/architecture.md`.
