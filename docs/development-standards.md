# Правила разработки

Обязательные конвенции — для текущей Python-версии и для целевой Go-версии
(`migration-to-go.md`). Часть правил уже соблюдается в коде (помечено ✅, со ссылкой на факт),
часть — целевые для переноса (📋).

## Валидация конфигурации — все ошибки разом, не fail-fast

✅ **Python (сейчас):** `Settings` — `pydantic_settings.BaseSettings`. Pydantic по конструкции
собирает все ошибки валидации полей в один `ValidationError`, не падает на первом невалидном
поле — это встроенное поведение библиотеки, не отдельно написанный код.

📋 **Go (цель):** pgx/chi не дают такого бесплатно — `config.Load(getenv func(string) string)
(*Config, error)` должен собирать `[]error` по каждому полю и в конце возвращать
`errors.Join(errs...)` с количеством ошибок в сообщении (паттерн sentrix,
`internal/config/config.go`) — реализовать явно, не полагаться на то, что "раз структура
проинициализировалась — значения корректны".

## Ошибки — sentinel-ошибки, не сравнение строк

📋 Go-версия: именованные sentinel-ошибки (`ErrDuplicatePackage`, `ErrBlacklisted`,
`ErrNotFound`), `errors.Is`/`fmt.Errorf("...: %w", ...)`. Python-версия сейчас использует
типизированные исключения (`app/core/errors.py`: `AuthError`, `ForbiddenError`,
`ConfigurationError` и т.д.) — тот же принцип, другой языковой механизм; переносить как есть.

## Внешние системы — за адаптером, с таймаутом/ретраями/circuit breaker

✅ Уже так в Python-версии: `ArtifactStore`/`VulnerabilityIndex`/`Notifier`/
`PackageManagerPlugin` — интерфейсы, реализации подменяемы (см. `architecture.md`,
"Интерфейсы адаптеров"); `app/core/http.py` — таймауты (`HTTP_TIMEOUT_SECONDS`), ретраи
(`HTTP_RETRIES`), circuit breaker (`CIRCUIT_BREAKER_FAIL_MAX`/`_RESET_SECONDS`).

📋 Go-версия переносит те же интерфейсы 1:1 как Go `interface` — см. `migration-to-go.md`.
Тайминги (`HTTP_TIMEOUT_SECONDS=30`, `HTTP_RETRIES=3`, `CIRCUIT_BREAKER_FAIL_MAX=5`,
`CIRCUIT_BREAKER_RESET_SECONDS=60`) переносятся как дефолты без изменений — это уже подобранные
на практике значения, не место для "лучше на глаз".

## Секреты и конфигурация

✅ Реестры (Nexus/Artifactory), справочники модерации (`config/blacklist.yml`,
`config/licenses.yml`) — через admin API + файлы, перечитываемые по `POST
/api/v1/admin/reload`, не через переменные CI консюмеров (сервис — не CI-обвязка, см.
`stakeholders.md`).

📋 Устранить `LOCAL_AUTH_SECRET` как статический секрет конфигурации — заменяется PAT +
server-side сессиями, см. `docs/auth.md`. До переноса на Go — минимум, провалидировать при
`APP_ENV=prod` (см. `architecture.md`, "Известный риск конфигурации по умолчанию").

## Тестирование

См. отдельно [`docs/testing.md`](testing.md) — три уровня по образцу `sentrix`
(юнит/интеграционные на реальном Postgres/реальной очереди/реальном хранилище/e2e на реально
собранном бинарнике), с явным разбором, чем текущие Python-тесты отличаются от этой модели.

## Комментарии и документация

Комментарии — на русском, объясняют ПОЧЕМУ (неочевидное ограничение, обоснование решения,
ссылка на баг/риск), не ЧТО делает код. Пример из уже существующего кода: комментарий про
72-байтный лимит bcrypt в `app/core/security.py` — объясняет ограничение библиотеки, не
пересказывает вызов `.encode()`. Без эмодзи нигде — ни в коде, ни в документации.

## Definition of Done для эпика/фичи

- Реализована логика + тесты соответствующего уровня (`docs/testing.md`).
- Если меняется API — обновлён `docs/api.md`.
- Если меняется набор ролей/прав — обновлены `docs/stakeholders.md`/`docs/auth.md` и правки
  прав пишутся в `audit_log` (см. `docs/auth.md`, разрыв про `sync_user`).
- Если добавлена новая метрика Prometheus — добавлен алерт/панель (по аналогии с
  `deploy/prometheus/alerts.yml`/`deploy/grafana/...` у sentrix — у этого сервиса пока нет
  собственных provisioning-файлов дашборда, завести при переносе на Go).
- Если фича — перенос существующего поведения на Go — сверка golden-file с Python-версией до
  отключения старого пути (см. `migration-to-go.md`).
