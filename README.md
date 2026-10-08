# Сервис модерации внешних пакетов

Веб-сервис модерации внешних (open-source) пакетов. Сервис — **единственный вход**: разработчик
получает ссылку и заводит пакеты только здесь. Правка `package_list.txt` и merge request'ы как
способ заявить пакет не поддерживаются; сервис ничего не пишет в репозитории.

Поддерживаемые менеджеры: `pypi`, `npm`, `go`, `nuget`.

## Как это работает

```
Actor → nginx → Web UI
              → API ──┬── Поиск (имя, версия, менеджер)          → БД
                      ├── Добавление (имя, версия, менеджер) ─────┐
                      │      ↑ Парсер (файл с зависимостями) ─────┤
                      │                                            ↓
                      │                              Проверка наличия пакета (БД)
                      │                                            ↓
                      │        1. Blacklist → 2. Карантин → 3. Лицензия → 4. Скачивание
                      │                                            ↓ (Network, HTTP_PROXY)
                      │                            Временный репозиторий артефактори
                      │                                            ↓
                      │                              Проверка на уязвимости (osv-scanner)
                      │                                            ↓
                      │                                  Песочница (вердикт + отчёт)
                      │                                            ↓
                      │                   Публикация: перенос в репозиторий менеджера
                      └── Настройка → .env
```

Конвейер **последовательный** с одним исключением: шаг «Лицензия», не пройденный автоматически,
не останавливает прогон. Пакет уходит на скачивание и проверку уязвимостей, чтобы DevSecOps увидел
его в своей очереди сразу, а не после решения юриста — согласования двух ролей идут параллельно.
Опубликован пакет не будет, пока не снята каждая блокировка. Состояние каждого шага пишется в БД,
поэтому в UI всегда видно, на чём именно остановился пакет. Подробности —
в [`docs/architecture.md`](docs/architecture.md).

## Быстрый старт

Разворачиваете на своей машине впервые — берите
[`docs/local-setup.md`](docs/local-setup.md): там тот же путь по шагам, вместе
с учётками, снапшотом базы уязвимостей и разбором типичных «почему не
работает».

```bash
git clone <repo> && cd Moder_repo
make env                  # создаст .env из .env.example
$EDITOR .env              # заполните секреты и адреса (см. раздел ниже)

# всё своё, включая Nexus и Keycloak:
make up-all

# либо: свой сервис + внешние Nexus/Keycloak заказчика (адреса из .env)
make up

make bootstrap            # справочники, проверка репозиториев артефактори, демо-данные
make logs                 # логи api-go и worker-go

docker compose run --rm migrate-go schema   # схема базы против кода: чего не хватает
```

При пустой базе сервис создаёт локального администратора из обязательных
`ADMIN_USERNAME`/`ADMIN_PASSWORD`. Задайте уникальный пароль до первого
запуска. Остальные локальные учётки создаются на
странице «Настройка → Пользователи и роли».

После старта:

| Что | Адрес |
| --- | --- |
| Web UI | http://localhost:8080 |
| OpenAPI (Swagger) | http://localhost:8080/api/docs |
| Healthcheck | http://localhost:8080/health |
| Метрики Prometheus | http://localhost:8080/metrics |
| Keycloak (профиль `sso`) | http://localhost:8081 |
| Nexus (профиль `nexus`) | http://localhost:8082 |

Тестовые учётные записи для локального стенда создавайте через bootstrap или
страницу «Настройка → Пользователи и роли»; готовые пароли в репозитории не
публикуются.

### Вход через Keycloak

Keycloak проксируется nginx'ом на том же origin, что и приложение: пути
`/realms/`, `/resources/`, `/admin/` и `/js/` уходят на `keycloak:8080`
(`nginx/snippets/app.conf`). Поэтому отдельный порт и отдельный сертификат для
Keycloak наружу не нужны — достаточно того же 443, на котором работает сервис:

```ini
OIDC_ISSUER=http://keycloak:8080/realms/moderation
OIDC_PUBLIC_ISSUER=https://<ваш-хост>/realms/moderation
OIDC_CLIENT_ID=moderation-web
OIDC_PUBLIC_BASE_URL=https://<ваш-хост>
```

Эти значения только впервые заполняют OIDC-настройку в Postgres. Затем issuer,
client id/secret, публичный адрес и текст кнопки меняются на странице
«Настройка → OIDC / Keycloak» и применяются сразу. Предпочтителен один canonical
issuer, доступный и backend, и браузеру. Для встроенного compose-профиля
поддерживается прежняя пара адресов: discovery/JWKS и обмен code идут через
внутренний `OIDC_ISSUER`, а браузер и проверка claim `iss` используют
`OIDC_PUBLIC_ISSUER`.

Админконсоль Keycloak: `https://<ваш-хост>/admin` (или напрямую
`http://<хост>:8081` — этот порт остаётся для локальной отладки).

**Почему не отдельный порт.** Так было раньше, и это ломалось тремя способами
подряд: Keycloak без сертификата HTTPS вообще не поднимает (порт опубликован, а
внутри контейнера на нём никто не слушает — браузер получает
`ERR_CONNECTION_REFUSED`); отдельный порт обычно закрыт фаерволом; а
самоподписанный сертификат убивает вход совсем незаметно — SPA дёргает
`.well-known` через `fetch`, и тот падает на невалидном сертификате молча, без
кнопки «всё равно перейти».

Отдельный порт Keycloak (`KEYCLOAK_TLS_PORT` + оверлей `docker-compose.tls.yml`)
нужен теперь только если вы сознательно выставляете Keycloak в обход nginx.

### Остановка и повторный запуск

`bootstrap` нужен **только один раз**: база и артефакты Nexus лежат в именованных
volume'ах (`pgdata`, `nexus-data`) и переживают остановку. Скачанные пакеты
хранятся не рядом, а в самом артефактори — во временном репозитории до конца
проверок и в репозитории своего менеджера после.

```bash
make down                 # остановить (данные остаются)
make up-all               # поднять снова — с теми же данными
make ps                   # убедиться, что всё Up
```

Что стоит знать про повторный старт:

* **Keycloak** не хранит H2 в volume, поэтому realm `moderation` импортируется заново
  при каждом старте — демо-учётки на месте, но ручные правки в консоли Keycloak теряются.
* **Nexus** поднимается 1–3 минуты; до этого шаг публикации будет отбиваться таймаутом.
* **Nexus 3.96+ (`sonatype/nexus3:latest`) требует принятия EULA** через
  `POST /service/rest/v1/system/eula` (тело — `{"accepted": true, "disclaimer": "<текст из
  GET того же пути>"}`) прежде чем разрешит любые операции с содержимым репозиториев. Без
  этого шага (который `make bootstrap` сейчас не делает) все запросы к содержимому, включая
  внутренние от самого сервиса, получают `403 Forbidden`, а не `404` — шаг «Выгрузка в
  артефактори» будет падать на первом же пакете с непонятной на первый взгляд ошибкой.
  Обнаружено и подтверждено локальной проверкой (см. `CHANGELOG.md`, "Проверено локально").
* После правок `.env` или `config/` — `make restart` (это `up -d`, а не `docker compose
  restart`: переменные из `env_file` фиксируются при создании контейнера).
* `make clean` — это `down -v`: удаляет volume'ы вместе с базой и Nexus.
  После него `make bootstrap` обязателен.

### Развёртывание на хосте, доступном по имени

Локально всё работает по HTTP на `localhost`. Как только сервис выставляется под
настоящим именем, используйте HTTPS: access/refresh-сессии и OIDC callback нельзя
передавать по открытому каналу. PKCE/state/nonce теперь создаёт и проверяет backend,
а браузер не получает токены Keycloak.

Порядок такой:

```bash
# 1. Сертификат. Самоподписанный — для проверки; в бою берите у внутреннего CA
#    и кладите файлы в nginx/certs/ и keycloak/certs/ теми же именами.
make certs DOMAIN=service.example.com

# 2. Значения в .env (полный список с пояснениями — в .env.example)
#    PUBLIC_BASE_URL=https://service.example.com
#    NGINX_PORT=80
#    NGINX_TLS_PORT=443
#    NGINX_FORCE_HTTPS=true
#    TLS_COMMON_NAME=service.example.com
#    KEYCLOAK_TLS_PORT=8443
#    OIDC_PUBLIC_ISSUER=https://service.example.com:8443/realms/moderation
#    OIDC_PUBLIC_BASE_URL=https://service.example.com

# 3. Поднять с общим сертификатом для nginx и Keycloak
docker compose -f docker-compose.yml -f docker-compose.override.yml \
               -f docker-compose.tls.yml --profile sso --profile nexus up -d --build

# 4. Bootstrap (сам дождётся готовности Nexus)
make bootstrap
```

Что здесь важно и неочевидно:

* Для встроенного Keycloak `OIDC_ISSUER` остаётся внутренним, а
  `OIDC_PUBLIC_ISSUER` — браузерным. Для внешнего корпоративного IdP обычно
  достаточно одного публичного issuer, доступного контейнеру API.
* **После правки `PUBLIC_BASE_URL` пересоберите Keycloak.** Внешний адрес попадает в
  `redirectUris` клиента на сборке образа; без пересборки Keycloak отклонит редирект
  после логина: `docker compose --profile sso up -d --build keycloak`.
* **Оверлей `docker-compose.tls.yml` не обязателен.** Без него Keycloak в dev-режиме
  сгенерирует собственный самоподписанный сертификат — работать будет, но браузер
  попросит подтверждение дважды: для адреса сервиса и для адреса Keycloak.
* **Свой сертификат можно не класть вовсе.** Если `nginx/certs/` пуст, nginx при старте
  сгенерирует самоподписанный на `TLS_COMMON_NAME` — HTTPS поднимется в любом случае.
* **Всё делать без `sudo`.** Достаточно быть в группе `docker`. Пара запусков
  `sudo docker compose` создаёт файлы volume'ов и `~/.docker/config.json` от root, после
  чего обычный запуск перестаёт их читать.

Приватные ключи в репозиторий не попадают: `certs/`, `nginx/certs/` и `keycloak/certs/`
закрыты в `.gitignore`, отслеживаются только пустые `.gitkeep` — они нужны, чтобы каталоги
существовали в чистом клоне и `COPY certs/` в Dockerfile не уронил сборку.

### Docker Desktop + WSL2: «error mounting … no such file or directory»

Симптом — контейнер не стартует с ошибкой вида:

```
error mounting "/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/..." to rootfs
at "/opt/keycloak/data/import/realm-moderation.json": no such file or directory
```

Это известная поломка bind-mount'ов Docker Desktop в WSL2: staging-путь для файла с
хоста перестаёт резолвиться. Поэтому конфиги, которые не нужно править на лету,
зашиты в образы, а не монтируются: конфиги nginx (`nginx/https.conf`, `nginx/snippets/`,
см. `nginx/Dockerfile`) и
`keycloak/realm-moderation.json` (см. `keycloak/Dockerfile`). Правка применяется
пересборкой соответствующего сервиса:

```bash
docker compose --profile sso up -d --build keycloak
docker compose up -d --build nginx
```

Если ошибка всё же возникла, помогает пересоздать контейнер (`docker compose up -d
--build --force-recreate <сервис>`); если и это не помогло — перезапуск Docker Desktop,
после которого staging-каталоги создаются заново.

### Если пакет долго «проверяется»

Очередь в PostgreSQL разбирает `worker-go`. Чтобы упавший worker не превращался
в «заявка висит вечно», в сервисе есть страховка — сторож внутри `api-go`. Он раз в
`PIPELINE_WATCHDOG_INTERVAL_SECONDS` ищет пакеты, стоящие в очереди дольше
`PIPELINE_STUCK_AFTER_SECONDS`, захватывает строку атомарно и запускает конвейер.
Двойного прогона не будет благодаря `FOR UPDATE SKIP LOCKED`. Подробнее — в
[`docs/architecture.md`](docs/architecture.md#пакет-не-должен-зависать-в-очереди).

То же самое видно на экране «Настройка» (блок «Обработка очереди») и в
`GET /api/v1/system/status`. Если ждать прохода сторожа не хочется:

```bash
make run-pending          # прогнать зависшие пакеты прямо сейчас
```

Поднять сам worker, если он лёг: `docker compose up -d worker-go` и
`docker compose logs worker-go --tail=60`.

Логи структурные (JSON), сообщения — на русском. Грепать по русскому слову можно, но
надёжнее по имени логгера: оно ASCII и не зависит от языка сообщения.

```bash
docker compose logs api-go --tail=100
docker compose logs worker-go --tail=100
```

### Первый рабочий инструмент — REST API

Заводить пакеты можно сразу из CI и `curl`, до работы с UI:

```bash
curl -sS -X POST http://localhost:8080/api/v1/requests \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: ci-build-4211' \
  -d '{
        "manager": "pypi",
        "packages": [{"name": "requests", "version": "2.31.0"}],
        "reason": "Сервис выставления счетов, спринт 41"
      }'
```

Полный набор примеров, включая загрузку файла зависимостей и блокирующий вариант для CI, — в
[`docs/api.md`](docs/api.md).

## Конфигурация

Все политики и адреса задаются переменными окружения и применяются при старте.
**UI-редактирования настроек нет**: экран «Настройка» показывает действующие значения только на
чтение, с указанием имени переменной. Изменение — правка `.env` и рестарт (`make restart`).

Описание каждой переменной — в [`.env.example`](.env.example). Ключевые группы:

| Группа | Переменные | Смысл |
| --- | --- | --- |
| Политики | `QUARANTINE_DAYS`, `VULN_MAX_SCORE`, `BLACKLIST_FILE`, `ALLOWED_LICENSES_FILE` | сроки карантина, порог уязвимости 0..100, файлы правил |
| Реестры и сеть | `REGISTRY_*`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | откуда качаем и через какой прокси |
| Артефактори | `ARTIFACT_STORE`, `ARTIFACT_BASE_URL`, `ARTIFACT_REPO_*` | куда публикуем; один инстанс на все менеджеры |
| Временная зона | `ARTIFACT_REPO_STAGING`, `ARTIFACT_REPO_REPORTS` | где пакет лежит, пока идут проверки, и где живут отчёты |
| Песочница | `SANDBOX_URL`, `SANDBOX_TOKEN`, `SANDBOX_PRIORITY` | динамическая проверка архива, шаг `sandbox_scan` |
| Уязвимости | `OSV_DB_SOURCE`, `OSV_PYPI_SNAPSHOT_PATH`, `OSV_NPM_SNAPSHOT_PATH`, `OSV_SYNC_INTERVAL_SECONDS`, `OSV_MAX_STALENESS_DAYS` | локальные снапшоты PyPI/npm, без сети к osv.dev |
| Доступ | `OIDC_*`, `LOCAL_AUTH_ENABLED` | SSO/локальный вход; роли назначаются в самом сервисе |
| GitLab | `GITLAB_*`, `FERNET_KEY` | чтение файлов зависимостей, шифрование токенов |
| Лимиты | `MAX_UPLOAD_SIZE_BYTES`, `MAX_PACKAGES_PER_REQUEST`, `RATE_LIMIT_REQUESTS_PER_MINUTE` | защита от перегрузки |

`config/blacklist.yml` и `config/licenses.yml` монтируются в контейнер и перечитываются при старте
и по `POST /api/v1/admin/reload` (роль `admin`, кнопка на экране «Настройка»).

### Прокси

Весь исходящий трафик наружу идёт через корпоративный прокси: `HTTP_PROXY`, `HTTPS_PROXY`,
`NO_PROXY` пробрасываются в `api-go` и `worker-go`. Внутренние адреса (`db`, `nexus`,
`keycloak`) обязательно перечислены в `NO_PROXY`.

## Профили docker compose

| Команда | Что поднимается |
| --- | --- |
| `docker compose up -d` | сервис (`api-go`, `worker-go`, `migrate-go`) + db (Nexus и Keycloak — внешние, из `.env`) |
| `docker compose --profile nexus up -d` | плюс собственный Sonatype Nexus |
| `docker compose --profile sso up -d` | плюс собственный Keycloak с готовым realm |
| `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | прод: healthcheck'и, `restart: unless-stopped`, без hot reload |

`docker-compose.override.yml` подхватывается автоматически и публикует порты инфраструктуры
для локальной разработки. В проде он не используется (см. команду выше).

## Роли

| Роль | Права |
| --- | --- |
| `admin` | всё, включая аудит-лог и `POST /api/v1/admin/reload` |
| `devsecops` | решения по уязвимостям и карантину, все заявки |
| `legal` | решения по лицензиям, все заявки |
| `developer` | создание заявок, свои заявки, чтение базы пакетов, ответы в обсуждениях |

Добавлять пакеты может любая роль. Права проверяются в API, не только в UI. Каждое действие пишется
в аудит-лог: кто, что, когда, старое/новое значение, источник (UI / REST API / фоновая задача / CLI).

Вход логин/пароль для локальных пользователей и сервисных учёток включается
флагом `LOCAL_AUTH_ENABLED` (в prod по умолчанию `false`):

```bash
make cli ARGS="create-service-account ci-bot --roles developer"
```

## Разработка

```bash
# Backend на Go
cd backend-go
go test -p 1 ./...                         # интеграционным тестам нужен PostgreSQL
gofmt -w .
go vet ./...

# Frontend
cd frontend
npm install
npm run dev                                # http://localhost:5173, API проксируется на :8000
```

Миграции:

```bash
make migrate          # применить SQL-миграции backend-go/migrations
make migrate-status   # показать применённые и ожидающие миграции
make schema           # сверить фактическую схему с ожиданиями кода
```

Полезные команды CLI (`moderation` внутри Go-образа):

```bash
make cli ARGS="--help"
make sync-osv                                        # загрузить снапшот базы OSV из артефактори
make rescan                                          # перепроверить одобренные пакеты
make reload                                          # перечитать blacklist и лицензии
make import-list FILE=./package_list.txt MANAGER=pypi   # одноразовый импорт при внедрении
```

### Настройка через web

Администратор может менять несекретные адреса, имена репозиториев, пороги и
таймауты на странице **«Настройка → Конфигурация и состояние»**. Значения
хранятся в таблице `app_setting` и имеют приоритет над `.env`. После сохранения
PostgreSQL уведомляет оба процесса: `api-go` в фоне собирает новый роутер и
атомарно переключает трафик без остановки HTTP listener, а `worker-go`
корректно завершается и поднимается политикой `restart: unless-stopped`.
Ручной перезапуск и пересборка образов при следующих изменениях не нужны.

Секреты (`DATABASE_URL`, токены, пароли, ключ подписи) остаются в `.env` или
секрет-хранилище и в API не возвращаются. Внутренний адрес Nexus задаётся в
`ARTIFACT_BASE_URL`, а адрес для браузера и команд установки — отдельно в
`ARTIFACT_PUBLIC_BASE_URL`; это не даёт ссылкам вида `http://nexus:8081/...`
попасть разработчику.

На вкладке **«Пользователи и роли»** роли назначаются внутри сервиса. Можно
создать локального пользователя или заранее подготовить профиль OIDC; при
следующем входе claims Keycloak не перезапишут выданные приложением роли.

## Документация

- [`docs/status.md`](docs/status.md) — **состояние дел**: что сделано, какие проблемы вылезали и чем кончились, план и долги
- [`docs/architecture.md`](docs/architecture.md) — схема конвейера, состояния, схема БД, интерфейсы адаптеров
- [`docs/stakeholders.md`](docs/stakeholders.md) — роли, их цели и зоны ответственности за конфигурацию/интеграции
- [`docs/user-stories.md`](docs/user-stories.md) — что закрыто для каждой роли и чем именно, статус по сверке с кодом
- [`docs/auth.md`](docs/auth.md) — модель аутентификации, сессий и управления пользователями
- [`docs/design-system.md`](docs/design-system.md) — единая визуальная палитра с sentrix, что перекрашено и что осталось
- [`docs/development-standards.md`](docs/development-standards.md) — обязательные конвенции, текущие и целевые (Go)
- [`docs/testing.md`](docs/testing.md) — принципы тестирования из sentrix и разбор, чем текущие тесты от них отличаются
- [`docs/ci-parity-gaps.md`](docs/ci-parity-gaps.md) — явный трекинг разрывов с функциональностью CI-версии (pt-package-review/moderated), чтобы ничего не потерялось при переносе на Go
- [`docs/flows.md`](docs/flows.md) — детальный флоу сервиса и каждой роли (по коду UI+API), с наблюдениями для корректировки функционала/плана
- [`docs/ux-wishlist.md`](docs/ux-wishlist.md) — неотфильтрованный брейншторм: что можно сделать для удобства каждой роли, требует приоритизации
- [`docs/configuration-model.md`](docs/configuration-model.md) — переход от `.env`+рестарт к admin API + БД: что конфигурируется через UI, что остаётся bootstrap-исключением
- [`docs/api.md`](docs/api.md) — примеры curl для обоих способов добавления и остальных эндпоинтов
- [`docs/integrations.md`](docs/integrations.md) — свой Artifactory, GitLab, прокси
- [`docs/osv-snapshot.md`](docs/osv-snapshot.md) — формат снапшота OSV и поведение при его недоступности
- [`docs/migration-from-ci.md`](docs/migration-from-ci.md) — переход с `package_list.txt` и CI-проверок
- [`docs/migration-to-go.md`](docs/migration-to-go.md) — исторический план завершённого переноса backend с Python на Go
- [`docs/scanning-and-reports.md`](docs/scanning-and-reports.md) — как устроены проверки на SAST и политический контент и где брать файлы отчётов (JSON и HTML)

## Что сервис намеренно не делает

- Не использует proxy-репозитории артефактори в потоке модерации: артефакт качается напрямую из
  реестра пакетного менеджера через `HTTP_PROXY`.
- Не обращается к osv.dev во время проверки: решение принимается по локальному снапшоту OSV из
  артефактори.
- Не пишет в репозитории и не открывает merge request'ы.
- Не отправляет внешние уведомления (Mattermost, Telegram) — только уведомления внутри сервиса,
  через абстракцию `Notifier` с реализацией `InAppNotifier`.
