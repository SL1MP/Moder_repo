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
                      │                                     S3 (MinIO)
                      │                                            ↓
                      │                              Проверка на уязвимости (osv-scanner)
                      │                                            ↓
                      │                      Политические баннеры (YARA) + SAST (semgrep)
                      │                                            ↓
                      │                                    Выгрузка пакета → Nexus
                      └── Настройка → .env
```

Конвейер **последовательный** с одним исключением: шаг «Лицензия», не пройденный автоматически,
не останавливает прогон. Пакет уходит на скачивание и проверку уязвимостей, чтобы DevSecOps увидел
его в своей очереди сразу, а не после решения юриста — согласования двух ролей идут параллельно.
Опубликован пакет не будет, пока не снята каждая блокировка. Состояние каждого шага пишется в БД,
поэтому в UI всегда видно, на чём именно остановился пакет. Подробности —
в [`docs/architecture.md`](docs/architecture.md).

## Быстрый старт

```bash
git clone <repo> && cd Moder_repo
make env                  # создаст .env из .env.example
$EDITOR .env              # заполните секреты и адреса (см. раздел ниже)

# всё своё, включая Nexus и Keycloak:
make up-all

# либо: свой сервис + внешние Nexus/Keycloak заказчика (адреса из .env)
make up

make bootstrap            # миграции, справочники, бакет MinIO, репозитории Nexus, демо-данные
make logs                 # логи api, worker, beat
```

После старта:

| Что | Адрес |
| --- | --- |
| Web UI | http://localhost:8080 |
| OpenAPI (Swagger) | http://localhost:8080/api/docs |
| Healthcheck | http://localhost:8080/health |
| Метрики Prometheus | http://localhost:8080/metrics |
| Keycloak (профиль `sso`) | http://localhost:8081 |
| MinIO Console (dev) | http://localhost:9001 |
| Nexus (профиль `nexus`) | http://localhost:8082 |

Демо-учётные записи Keycloak (realm `moderation`): `dev.ivanov/dev`, `sec.petrov/sec`,
`legal.sidorova/legal`, `moderation.admin/admin`.

### Вход через Keycloak

Keycloak проксируется nginx'ом на том же origin, что и приложение: пути
`/realms/`, `/resources/`, `/admin/` и `/js/` уходят на `keycloak:8080`
(`nginx/snippets/app.conf`). Поэтому отдельный порт и отдельный сертификат для
Keycloak наружу не нужны — достаточно того же 443, на котором работает сервис:

```ini
OIDC_PUBLIC_ISSUER=https://<ваш-хост>/realms/moderation   # без порта
```

`OIDC_ISSUER` при этом остаётся внутренним (`http://keycloak:8080/realms/moderation`):
по нему api берёт JWKS внутри сети compose. Сервис принимает оба issuer'а
(`backend/app/core/config.py::accepted_issuers`), подпись у токена одна и та же.

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

`bootstrap` нужен **только один раз**: база, артефакты Nexus и объекты MinIO лежат в
именованных volume'ах (`pgdata`, `nexus-data`, `minio-data`) и переживают остановку.

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
* `make clean` — это `down -v`: удаляет volume'ы вместе с базой, Nexus и MinIO.
  После него `make bootstrap` обязателен.

### Развёртывание на хосте, доступном по имени

Локально всё работает по HTTP на `localhost`. Как только сервис выставляется под
настоящим именем, **HTTPS становится обязательным, а не желательным**: SPA считает
PKCE-challenge через `window.crypto.subtle`, а этот API браузер даёт только в secure
context — по HTTPS либо на `localhost`. По HTTP на внешнем имени вход через SSO падает
с `Cannot read properties of undefined (reading 'digest')`.

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

# 3. Поднять с общим сертификатом для nginx и Keycloak
docker compose -f docker-compose.yml -f docker-compose.override.yml \
               -f docker-compose.tls.yml --profile sso --profile nexus up -d --build

# 4. Bootstrap (сам дождётся готовности Nexus)
make bootstrap
```

Что здесь важно и неочевидно:

* **`OIDC_ISSUER` менять не нужно.** Он внутренний (`http://keycloak:8080/...`), api ходит
  по нему внутри сети compose. Браузерный адрес задаётся отдельно — `OIDC_PUBLIC_ISSUER`.
  Сервис принимает оба issuer'а, потому что Keycloak кладёт в claim `iss` тот адрес, по
  которому к нему обратились.
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

Очередь разбирает Celery-worker. Чтобы упавший worker не превращался в «заявка висит
вечно», в сервисе есть страховка — сторож внутри процесса API. Он раз в
`PIPELINE_WATCHDOG_INTERVAL_SECONDS` ищет пакеты, стоящие в очереди дольше
`PIPELINE_STUCK_AFTER_SECONDS`, и либо переотправляет задачу (если worker жив и потерялось
сообщение), либо прогоняет конвейер сам. Двойного прогона не будет: пакет захватывается
атомарно. Подробнее — в [`docs/architecture.md`](docs/architecture.md#пакет-не-должен-зависать-в-очереди).

Посмотреть, что происходит:

```bash
make queue-status         # жив ли worker, сколько пакетов зависло
make queue-doctor         # почему очередь стоит: разбор с готовым выводом
```

`queue-doctor` собирает в один отчёт всё, что иначе приходится добывать пятью разными
командами: heartbeat worker'а, доступность брокера, длину каждой очереди, ответ самого
worker'а на `inspect` и список очередей, которые он реально слушает. По этим данным
команда печатает вывод — что именно сломано и что делать. Она различает состояния,
снаружи неотличимые друг от друга:

| Что показывает отчёт | Что на самом деле |
| --- | --- |
| нет ни heartbeat, ни ответа на `inspect` | worker не запущен — смотрите логи контейнера |
| `inspect` отвечает, heartbeat молчит | образ без сигнала `worker_ready` — пересобрать worker |
| worker жив, но очередь никто не слушает | неверный `CELERY_QUEUES` — задачи уходят в никуда |
| worker жив, пакеты висят дольше порога | потерянное сообщение — разберёт сторож или `make run-pending` |

Отчёт рассчитан на то, чтобы отправить его целиком, не пересобирая вывод вручную.
Команда возвращает ненулевой код, если нашла проблему, — её можно звать из скриптов.

То же самое видно на экране «Настройка» (блок «Обработка очереди») и в
`GET /api/v1/system/status`. Если ждать прохода сторожа не хочется:

```bash
make run-pending          # прогнать зависшие пакеты прямо сейчас
```

Поднять сам worker, если он лёг: `docker compose up -d worker` и
`docker compose logs worker --tail=60`.

Логи структурные (JSON), сообщения — на русском. Грепать по русскому слову можно, но
надёжнее по имени логгера: оно ASCII и не зависит от языка сообщения.

```bash
docker compose logs api | grep app.services.watchdog   # что решил сторож при старте
docker compose logs worker | grep app.pipeline         # ход конвейера
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
| Временное хранилище | `S3_*` | MinIO как карантинная зона (не архив) |
| Артефактори | `ARTIFACT_STORE`, `ARTIFACT_BASE_URL`, `ARTIFACT_REPO_*` | куда публикуем; один инстанс на все менеджеры |
| Уязвимости | `OSV_SOURCE`, `OSV_SNAPSHOT_PATH`, `OSV_SYNC_CRON`, `OSV_MAX_STALENESS_DAYS` | локальный снапшот OSV, без сети к osv.dev |
| Доступ | `OIDC_*`, `ROLE_MAPPING_*`, `LOCAL_AUTH_ENABLED` | SSO и маппинг групп каталога в роли |
| GitLab | `GITLAB_*`, `FERNET_KEY` | чтение файлов зависимостей, шифрование токенов |
| Лимиты | `MAX_UPLOAD_SIZE_BYTES`, `MAX_PACKAGES_PER_REQUEST`, `RATE_LIMIT_REQUESTS_PER_MINUTE` | защита от перегрузки |

`config/blacklist.yml` и `config/licenses.yml` монтируются в контейнер и перечитываются при старте
и по `POST /api/v1/admin/reload` (роль `admin`, кнопка на экране «Настройка»).

### Прокси

Весь исходящий трафик наружу идёт через корпоративный прокси: `HTTP_PROXY`, `HTTPS_PROXY`,
`NO_PROXY` пробрасываются в `api`, `worker`, `beat`. Клиенты реестров используют эти значения
**явно** (см. `app/core/http.py`), а не полагаются на неявное поведение библиотеки. Внутренние
адреса (`db`, `redis`, `minio`, `nexus`, `keycloak`) обязательно перечислены в `NO_PROXY`.

## Профили docker compose

| Команда | Что поднимается |
| --- | --- |
| `docker compose up -d` | сервис + db, redis, minio (Nexus и Keycloak — внешние, из `.env`) |
| `docker compose --profile nexus up -d` | плюс собственный Sonatype Nexus |
| `docker compose --profile sso up -d` | плюс собственный Keycloak с готовым realm |
| `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | прод: healthcheck'и, `restart: unless-stopped`, без hot reload |

`docker-compose.override.yml` подхватывается автоматически и включает dev-режим: hot reload и порты
наружу. В проде он не используется (см. команду выше).

## Роли

| Роль | Права |
| --- | --- |
| `admin` | всё, включая аудит-лог и `POST /api/v1/admin/reload` |
| `devsecops` | решения по уязвимостям и карантину, все заявки |
| `legal` | решения по лицензиям, все заявки |
| `developer` | создание заявок, свои заявки, чтение базы пакетов, ответы в обсуждениях |

Добавлять пакеты может любая роль. Права проверяются в API, не только в UI. Каждое действие пишется
в аудит-лог: кто, что, когда, старое/новое значение, источник (UI / REST API / фоновая задача / CLI).

Fallback-вход логин/пароль — только для сервисных учёток, флаг `LOCAL_AUTH_ENABLED` (в prod `false`):

```bash
make cli ARGS="create-service-account ci-bot --roles developer"
```

## Разработка

```bash
# Backend без docker
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
DATABASE_URL=sqlite:// pytest              # тесты, порог покрытия 70%
ruff check app tests

# Frontend
cd frontend
npm install
npm run dev                                # http://localhost:5173, API проксируется на :8000
```

Миграции:

```bash
make revision M="описание изменения"   # автогенерация по моделям
make migrate                           # применить
```

Полезные команды CLI (`moderctl`):

```bash
make cli ARGS="--help"
make sync-osv                                        # загрузить снапшот базы OSV из артефактори
make rescan                                          # перепроверить одобренные пакеты
make reload                                          # перечитать blacklist и лицензии
make import-list FILE=./package_list.txt MANAGER=pypi   # одноразовый импорт при внедрении
```

## Документация

- [`docs/architecture.md`](docs/architecture.md) — схема конвейера, состояния, схема БД, интерфейсы адаптеров
- [`docs/stakeholders.md`](docs/stakeholders.md) — роли, их цели и зоны ответственности за конфигурацию/интеграции
- [`docs/user-stories.md`](docs/user-stories.md) — что закрыто для каждой роли и чем именно, статус по сверке с кодом
- [`docs/auth.md`](docs/auth.md) — целевая модель аутентификации (единая с sentrix/oakshield/vm.service)
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
- [`docs/migration-to-go.md`](docs/migration-to-go.md) — план переноса backend с Python на Go (решение принято, см. `docs/architecture.md`, "Целевой стек"); каркас — [`backend-go/`](backend-go/README.md), фаза 1 готова и проверена
- [`docs/scanning-and-reports.md`](docs/scanning-and-reports.md) — как устроены проверки на SAST и политический контент и где брать файлы отчётов (JSON и HTML)

## Что сервис намеренно не делает

- Не подтягивает транзитивные зависимости: проверяется и публикуется **только сам заявленный
  пакет**. При разборе lock-файла UI и API показывают предупреждение.
- Не использует proxy-репозитории артефактори в потоке модерации: артефакт качается напрямую из
  реестра пакетного менеджера через `HTTP_PROXY`.
- Не обращается к osv.dev во время проверки: решение принимается по локальному снапшоту OSV из
  артефактори.
- Не пишет в репозитории и не открывает merge request'ы.
- Не отправляет внешние уведомления (Mattermost, Telegram) — только уведомления внутри сервиса,
  через абстракцию `Notifier` с реализацией `InAppNotifier`.
