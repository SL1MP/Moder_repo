# План переноса backend на Go

Статус: **решение принято, перенос не начат**. Контекст решения и таблица "было/стало" —
`architecture.md`, раздел "Целевой стек". Этот документ — прямой аналог `docs/migration-and-
testing.md` и `docs/python-behavior-reference.md` в `sentrix` (тот сервис уже прошёл point
такой же переход — Python `reporter/` → Go `reporter-go`/Sentrix — и задокументировал его именно
так: план переноса + отдельный документ поведения legacy-версии, чтобы ничего не потерять).

## Что переносится без изменения по существу (домен уже спроектирован и провалидирован)

- **Схема БД** — сущности и их поля из `docs/architecture.md` ("Схема БД"): `user`,
  `package_manager`, `package`, `package_version`, `moderation_request`, `request_item`,
  `pipeline_step`, `vulnerability`, `code_finding`, `vuln_index_version`, `license`,
  `license_claim`, `comment`, `artifact`, `notification`, `audit_log`. Переносятся 1:1, включая
  `security_override_*`/`include_transitive`/`status_reason` и прочие поля, добавленные при
  сверке архитектуры с кодом.
- **Конвейер проверок** — порядок шагов (`db_check → blacklist → quarantine → license →
  download → vuln_scan → banner_scan → sast_scan → publish`), семантика `pass`/`warn`/`fail`/
  `defer`, три исхода `db_check` (approved/blacklisted/revoked), правило "лицензия не
  останавливает конвейер", таблица возобновления с шага. Переносится как контракт поведения, не
  как копия Python-кода.
- **Кросс-заявочное распространение решений** (`siblings_awaiting`/`_apply_to_siblings`) —
  решение по `package_version` применяется ко всем `request_item`, ждущим того же шага, across
  разных `moderation_request`. Это самая нетривиальная и самая легко теряемая при переносе
  деталь — см. `architecture.md`, соответствующий абзац. Стоит покрыть тестом первым делом, а не
  в конце.
- **RBAC-роли** — `admin`/`devsecops`/`legal`/`developer`, права проверяются в API, не только в
  UI; аудит-лог на каждое действие с указанием источника (UI/API/фон/CLI).
- **Auth** — OIDC/Keycloak (маппинг групп на роли через `ROLE_MAPPING_*`) + fallback
  логин/пароль для сервисных учёток. Протокол не меняется, меняется только реализация клиента
  (Go: `coreos/go-oidc` + `golang-jwt/jwt` — уже используются в oakshield и vm.service, готовый
  референс).
- **REST API контракт** — пути и формы ответов `/api/v1/*` (см. `docs/api.md`) должны остаться
  совместимы с уже существующим React/TS/Vite фронтендом: он не переписывается, значит его
  ожидания от API — это часть контракта, а не деталь реализации, которую можно менять по пути.
- **Интерфейсы адаптеров** (`ArtifactStore`, `VulnerabilityIndex`, `Notifier`,
  `PackageManagerPlugin` — `docs/architecture.md`, "Интерфейсы адаптеров") — переносятся как Go
  `interface`, с реализациями на каждый пакетный менеджер (`pypi`/`npm`/`go`/`nuget` уже есть в
  прототипе; остальные из `pt-package-review` — maven/nuget/docker/conan/terraform/luarocks/
  general — по мере необходимости, см. `../moderation-service/docs/user-stories.md`, Epic 3, для
  специфики каждого).

## Что меняется

| Было (Python) | Станет (Go) | Комментарий |
| --- | --- | --- |
| FastAPI, SQLAlchemy | chi + pgx, без ORM | как в sentrix/oakshield; vumana использует GORM поверх pgx — не повторять, это единственное расхождение между референсами и явно более тяжёлый выбор без видимого выигрыша |
| Alembic | golang-migrate, `NNNN_name.up/down.sql` | формат sentrix |
| Celery + Redis (worker/beat) | воркер на Go + NATS JetStream (очередь) + Valkey (KV/rate-limit) | Redis ≥7.4 — SSPL, не наш список permissive-OSS; NATS/Valkey — прямой референс из oakshield |
| MinIO (карантинная зона) | SeaweedFS, S3-совместимое API | MinIO — AGPL; интерфейс `ArtifactStore`-подобного адаптера не меняется, меняется только реализация под капотом (аналог замены в `docs/integrations.md`, "Добавление третьей реализации") |
| Watchdog на Python-потоке внутри API-процесса (`app/services/watchdog.py`) | тот же механизм на Go: heartbeat воркера в Valkey, сторож — горутина в API-процессе, атомарный захват `UPDATE ... WHERE status='queued'` | логика не меняется, меняется язык; см. `architecture.md`, "Пакет не должен зависать в очереди" — сохранить все три уровня защиты как есть |
| `config.py` (pydantic Settings) | `config.Load(getenv func(string) string) (*Config, error)` — все ошибки валидации разом, не fail-fast на первой | паттерн sentrix, уже сформулирован как обязательное правило в `docs/development-standards.md` этого прототипа ("возвращать все найденные ошибки разом") — Go-реализация должна следовать тому же |
| Один процесс `api` + отдельные `worker`/`beat` (3 разных Docker-образа/команды запуска) | опционально: один бинарник, режимы `--mode=api\|worker\|all` (как `cmd/reporter` в sentrix) | не обязательное решение, но заметно упрощает деплой и CI; решить отдельно, не блокирует остальной перенос |

## Чего перенос **не должен** случайно сделать

- Не менять контракт `/api/v1/*` без явной причины — фронтенд не переписывается.
- Не терять кросс-заявочное распространение решений (см. выше) — самое незаметное для тестов
  поведение, если писать тесты "по одной заявке за раз".
- Не централизовывать проверку `security_override_at` неправильно: в Python-прототипе она
  продублирована в каждом из трёх шагов сканирования содержимого (`vuln_scan`/`banner_scan`/
  `sast_scan`) — сознательный технический долг, отмеченный в `architecture.md`. При переносе на
  Go это стоит исправить (одна проверка в общем месте вызова шагов сканирования), а не
  копировать дублирование — perенос на новый язык это ровно тот момент, когда цена исправления
  минимальна.
- Не терять "недоступный сканер не значит чисто" — для OSV, YARA и semgrep-шагов недоступность
  инструмента обязана давать `warn`/`pending`, не тихий `pass`.

## Стратегия тестирования переноса

Прямой прецедент внутри той же организации — `vm.service`: Python(Django)→Go переезд,
описанный в `docs/history/MIGRATION_PLAN.md` того репозитория, использовал **golden-file
тесты**, перенесённые из Django-версии как есть — те же входные SBOM/фикстуры, сверка
byte-for-byte или JSON-diff вывода. Тот же подход подходит здесь:

1. Зафиксировать конвейер Python-прототипа как источник golden-результатов: набор
   `package_list`-фикстур (по одному сценарию на каждую ветку конвейера — blacklist/quarantine/
   license-parallel/vuln fail/banner warn/sast warn/publish/sibling-propagation) прогоняется
   через текущий FastAPI+Celery стек, результат (`pipeline_step` история, финальный статус)
   сохраняется как fixture.
2. Тот же набор фикстур прогоняется через Go-реализацию по мере готовности каждого шага;
   расхождение с golden-результатом — либо баг переноса, либо осознанное решение (тогда fixture
   обновляется явно, с пометкой почему).
3. Контрактные тесты API (`docs/api.md`) — тем же curl-примерами, что уже в документе, но как
   автоматизированный набор (unit/integration уровень из `docs/development-standards.md`
   `../moderation-service/`, если он останется актуален после переноса — см. открытый вопрос
   ниже), чтобы фронтенд не заметил переезда backend.

## Фазы (черновой порядок, уточняется отдельно)

1. ✅ **Каркас Go-сервиса** (`backend-go/`, см. его README) — `chi` роутер, `pgx`, миграции
   (схема Alembic перенесена в golang-migrate 1:1, без изменения структуры таблиц, `JSON` →
   `JSONB` — это была уступка ради SQLite в юнит-тестах, не нужна для pgx), `config.Load` с
   полной валидацией (все ошибки разом). Проверено на реальном Postgres.
2. 🔶 **Домен, репозиторий, pipeline runner (шаги 0–3)** — сделано: `internal/domain`,
   `internal/repo`, `internal/pipeline` (db_check/blacklist/quarantine/license с сохранением в
   БД, 5 интеграционных тестов на реальном Postgres — все PASS, см. `backend-go/README.md`).
   **Ещё нет**: шаги 4–8 (нужны адаптеры реестров/сканеров, фазы 3 и 5), обработчики решений
   ролей с sibling-propagation (`ReleaseQuarantine`/`DecideSecurity`/`DecideLicense` —
   `siblings_awaiting`/`_apply_to_siblings`, `security_override_*` централизованно — следующий
   шаг, самый рискованный по потере поведения).
3. Package-manager плагины — **все 10 обязательны, не бэклог "по мере необходимости"**
   (прямое замечание пользователя, см. `docs/ci-parity-gaps.md`): pypi/npm/go/nuget уже есть в
   прототипе, переносятся как реализации Go `PackageManagerPlugin` первыми. Порядок для
   оставшихся шести: **Docker — сразу следующий** (приоритет — отдельный прямой запрос
   пользователя: поиск уже загруженных образов особенно ценен из-за дороговизны повторной
   загрузки; поиск/`packages/check` уже общие для всех менеджеров, специфична только реализация
   плагина — multiarch-манифесты, сверка digest, `skopeo copy --all`), затем general → maven →
   terraform → luarocks → conan (от простого к сложному, полное обоснование порядка —
   `docs/ci-parity-gaps.md`). Каждый — отдельный, завершённый плагин с тестами, не заготовка.
4. Auth: OIDC/Keycloak + RBAC + fallback-логин.
5. Адаптеры: `ArtifactStore` — **приоритет `generic` (JFrog Artifactory), не `nexus`**:
   production реально работает только с Artifactory (см. `docs/ci-parity-gaps.md`, "Артефактори
   — production это JFrog Artifactory, не Nexus"); `NexusArtifactStore` переносить не первым и,
   возможно, не переносить вовсе, если у заказчика Nexus нигде не используется — уточнить перед
   тем, как тратить на это фазу. Плюс решить модель публикации (тот же документ: copy-в-
   Artifactory vs скачивание+`PUT`) до переноса, не после. SeaweedFS вместо MinIO — для временной
   карантинной зоны, не связано с выбором `ArtifactStore`. `VulnerabilityIndex` (OSV-снапшот),
   `Notifier` (in-app) — без изменений от исходного плана.
6. Воркер: NATS JetStream + Valkey вместо Celery/Redis; heartbeat + watchdog + атомарный захват.
7. REST API контракт — сверка с текущим `docs/api.md` и живым фронтендом (frontend не
   переписывается, только конфигурация вызовов, если понадобится).
8. Отключение Python-стека, `docker-compose.yml` этого репозитория переезжает на Go-образы;
   `backend/` (Python) архивируется, не удаляется молча — см. открытый вопрос ниже.
9. **Конфигурация — admin API + БД вместо `.env`+рестарт** (прямой запрос пользователя, см.
   `docs/configuration-model.md`): новые таблицы под Artifactory/Sandbox/реестры/политики
   блокировки/лимиты, admin API на запись (не только чтение, как сейчас), формы в UI. Делать
   сразу в Go-версии, не дважды (см. `configuration-model.md`, открытый вопрос №5) — естественно
   встраивается в фазы 3 (плагины менеджеров читают реестры из БД, не `.env`) и 5 (адаптеры
   `ArtifactStore`/будущий `SandboxClient` читают конфигурацию оттуда же).

## Открытые вопросы

1. **Что делать со старым `backend/` (Python) после переноса** — держать в git-истории как
   архив (аналог `docs/history/` у vm.service) или выносить в отдельную ветку (аналог
   orphan-ветки `master-go` у vm.service, `docs/MASTER-GO-BRANCH.md` того репозитория)?
2. **`../moderation-service/`** (более ранний Go-черновик, webhook/MR-центричная модель) —
   решение по нему всё ещё не принято (см. `docs/stakeholders.md`, последний раздел). Теперь,
   когда backend этого прототипа тоже переезжает на Go, стоит явно решить: удалить как
   нерелевантный (модель работы всё равно другая — self-service, не webhook), или вытащить из
   него что-то полезное (например, инвентаризацию функциональности `pt-package-review` по
   пакетным менеджерам, которых пока нет в прототипе — maven/docker/conan/terraform/luarocks/
   general).
3. Один бинарник (`--mode=api|worker|all`, как sentrix) или три отдельных (`api`/`worker`/
   `beat`, как сейчас) — решить до фазы 6.
