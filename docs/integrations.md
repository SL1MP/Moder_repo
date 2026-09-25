# Интеграции: свой Artifactory, GitLab, корпоративный прокси

## Артефактори

Абстракция `ArtifactStore` (`app/adapters/artifact_store.py`) скрывает конкретную реализацию за
общим интерфейсом. Выбор — переменной `ARTIFACT_STORE=nexus|generic`.

> **Важно при переносе с CI-версии**: production (`pt-package-review`/`moderated`) работает
> исключительно с **JFrog Artifactory**, Nexus там не используется вообще — см.
> `docs/ci-parity-gaps.md`, "Артефактори — production это JFrog Artifactory, не Nexus". Раздел
> ниже про Nexus описывает то, что уже реализовано и работает в прототипе (`nexus` —
> действительно значение по умолчанию в коде/`.env.example`), но при сверке с реальной
> инфраструктурой ориентир — раздел "Внешний Artifactory" и, ещё важнее, различие в самой
> модели публикации (copy внутри Artifactory у CI-версии vs скачивание+`PUT` здесь) —
> разобрано в `ci-parity-gaps.md`, там же открытый риск: неизвестно, разрешает ли реальный
> production Artifactory прямой `PUT` в moderated-репозитории.

### Sonatype Nexus (значение по умолчанию в коде — не то, что использует production)

Один инстанс на все менеджеры: hosted-репозиторий на каждый (`ARTIFACT_REPO_PYPI`,
`ARTIFACT_REPO_NPM`, `ARTIFACT_REPO_GO`, `ARTIFACT_REPO_NUGET`,
`ARTIFACT_REPO_DOCKER`, `ARTIFACT_REPO_CONAN`) плюс raw-репозиторий со снапшотами OSV
(`ARTIFACT_REPO_OSV`).
Обычные пакеты публикуются через Nexus REST API (`/service/rest/v1/...`), Docker —
через Registry API v2, Conan — через Conan v2 API. Аутентификация —
`ARTIFACT_USER`/`ARTIFACT_TOKEN`.

```bash
ARTIFACT_STORE=nexus
ARTIFACT_BASE_URL=https://nexus.internal.example.com
ARTIFACT_USER=moderation-service
ARTIFACT_TOKEN=***
ARTIFACT_REPO_PYPI=pypi-internal
ARTIFACT_REPO_NPM=npm-internal
ARTIFACT_REPO_GO=go-internal
ARTIFACT_REPO_NUGET=nuget-internal
ARTIFACT_REPO_DOCKER=docker-internal
ARTIFACT_REPO_CONAN=conan-internal
ARTIFACT_DOCKER_REGISTRY_URL=http://nexus:8081/docker-internal
ARTIFACT_DOCKER_PUBLIC_URL=https://nexus.internal.example.com/docker-internal
ARTIFACT_REPO_OSV=osv-snapshots
OSV_PYPI_SNAPSHOT_PATH=osv/latest/osv-pypi.zip
OSV_NPM_SNAPSHOT_PATH=osv/latest/osv-npm.zip
```

Для Docker создайте hosted repository формата Docker. В Nexus 3.83+ включите
path-based routing: тогда worker публикует в
`ARTIFACT_DOCKER_REGISTRY_URL`, а разработчик получает команду вида
`docker pull nexus.internal.example.com/docker-internal/postgres:14.23@sha256:...`.
Если используется отдельный connector port, оба Docker URL задаются без
`/docker-internal`, но с соответствующим внутренним/внешним портом.

Публикацию выполняет `skopeo copy --all --preserve-digests`: перед запуском
архив staging безопасно распаковывается приложением в OCI layout, чтобы
непривилегированному пользователю контейнера не требовался `chown`. В Nexus попадают
исходный multi-platform index, manifests всех платформ, configs и layers.
`.oci.tar.gz` остаётся только временным транспортным форматом staging и после
успешной публикации удаляется; разработчик его не скачивает.

Для Conan создайте **hosted repository формата Conan 2**, а не raw. Сервис
публикует проверенный `conan_export.tgz` по исходной recipe revision через
нативный Conan v2 API; Python-код рецепта при публикации не исполняется.
Модерируется именно рецепт, а не все бинарные `package_id`: набор бинарников
зависит от compiler/arch/build_type/options и заранее не ограничен. Разработчик
подключает Nexus и при необходимости собирает бинарник из одобренного рецепта:

```bash
conan remote add internal https://nexus.internal.example.com/repository/conan-internal
conan install --requires=boost/1.91.0 -r internal --build=missing
```

Если Nexus у заказчика уже есть, свой контейнер не поднимается: не указывайте
`--profile nexus`, укажите внешний `ARTIFACT_BASE_URL`. Репозитории `make bootstrap` создаёт
автоматически (`ArtifactStore.ensure_repositories`), если их ещё нет — идемпотентно.

Go-модули публикуются в raw-репозиторий по схеме, совместимой с `GOPROXY`: путь
`{module}/@v/{version}.zip` (модуль экранируется по правилам Go: заглавные буквы → `!строчная`).

### Внешний Artifactory (JFrog или совместимый)

```bash
ARTIFACT_STORE=generic
ARTIFACT_BASE_URL=https://artifactory.example.com/artifactory
ARTIFACT_AUTH_TYPE=token          # basic | token
ARTIFACT_TOKEN=***
ARTIFACT_REPO_PYPI=pypi-local
ARTIFACT_REPO_NPM=npm-local
ARTIFACT_REPO_GO=go-local
ARTIFACT_REPO_NUGET=nuget-local
ARTIFACT_REPO_OSV=generic-local
# Шаблоны путей загрузки на каждый менеджер: {repo}, {name}, {normalized_name}, {version}, {filename}
ARTIFACT_PATH_TEMPLATE_PYPI={repo}/{name}/{filename}
ARTIFACT_PATH_TEMPLATE_NPM={repo}/{name}/-/{filename}
ARTIFACT_PATH_TEMPLATE_GO={repo}/{name}/@v/{filename}
ARTIFACT_PATH_TEMPLATE_NUGET={repo}/{name}/{version}/{filename}
```

Для Docker `ARTIFACT_REPO_DOCKER` должен указывать на локальный репозиторий
типа Docker/OCI с API v2. Сервис публикует не файл `.oci.tar.gz`, а нативный
граф OCI через `/artifactory/api/docker/{repo}/v2`: все blobs, manifests
платформ и исходный multi-platform index под тегом. Поэтому digest тега во
внутреннем Artifactory совпадает с Index digest из заявки.

Для остальных менеджеров публикация — `PUT` по собранному из шаблона пути с
заголовком `X-Checksum-Sha256`. Тот же адаптер читает произвольный файл
(`read_file`/`stat_file`) — через него забирается снапшот OSV, поэтому
`ARTIFACT_REPO_OSV`, `OSV_PYPI_SNAPSHOT_PATH` и
`OSV_NPM_SNAPSHOT_PATH` работают одинаково для обеих реализаций.

### Добавление третьей реализации

Реализуйте `ArtifactStore` (`app/adapters/artifact_store.py`) и подключите в
`get_artifact_store()`. Остальной код (конвейер, отзыв, перепроверка) обращается только к
абстракции и правок не требует.

## GitLab (только чтение)

Используется для одного способа заведения — чтения файла зависимостей из приватного проекта от
имени пользователя. Ничего не коммитится, merge request'ы не открываются.

### Настройка OAuth-приложения

1. GitLab → Admin Area → Applications (или Group/Project → Settings → Applications для
   self-managed без прав администратора).
2. Redirect URI: `https://<ваш-домен>/api/v1/gitlab/callback` (должен совпадать с
   `GITLAB_OAUTH_REDIRECT_URI`).
3. Scopes: `read_api`, `read_repository`. Больше ничего не запрашивается.
4. Сохранённые `client_id`/`client_secret` — в `.env`:

```bash
GITLAB_URL=https://gitlab.example.com
GITLAB_OAUTH_CLIENT_ID=***
GITLAB_OAUTH_CLIENT_SECRET=***
GITLAB_OAUTH_REDIRECT_URI=https://moderation.example.com/api/v1/gitlab/callback
FERNET_KEY=***   # см. ниже
```

Ключ шифрования refresh-токенов:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Без `FERNET_KEY` подключение GitLab вернёт `configuration_error` — сервис намеренно отказывается
хранить токены в открытом виде.

### Поток

1. Пользователь в профиле нажимает «Подключить GitLab» → `GET /api/v1/gitlab/authorize` отдаёт
   ссылку авторизации (Authorization Code, без PKCE — конфиденциальный клиент).
2. GitLab перенаправляет на `GET /api/v1/gitlab/callback?code=...`; сервис обменивает код на
   access/refresh токены, шифрует Fernet и сохраняет в `user.gitlab_*_token_enc`. Токены **не
   возвращаются** ни в одном ответе API.
3. `POST /api/v1/gitlab/requests` читает файл по `project` (ID или `namespace/name`), `path`,
   `ref` (ветка/тег/commit sha) через `GET /api/v4/projects/:id/repository/files/:path/raw` от
   имени пользователя.
4. Просроченный access-токен обновляется автоматически по refresh-токену прямо во время запроса.

### Отзыв доступа

`DELETE /api/v1/gitlab/connection` очищает токены пользователя. Отзыв OAuth-приложения на стороне
GitLab (Profile → Applications → Revoke) тоже сработает — следующий запрос вернёт ошибку, и
пользователю нужно будет подключиться заново.

## Корпоративный прокси

Весь исходящий трафик наружу (реестры пакетных менеджеров, GitLab, api.osv.dev в dev-режиме) идёт
через `HTTP_PROXY`/`HTTPS_PROXY`. Внутренние адреса — `db`, `nexus`, `keycloak`,
`api`, `web`, `nginx` (и всё, что резолвится внутри docker-сети) — обязательно перечислены в
`NO_PROXY`, иначе запросы к ним тоже пойдут через прокси и, скорее всего, упадут.

```bash
HTTP_PROXY=http://proxy.corp.example.com:3128
HTTPS_PROXY=http://proxy.corp.example.com:3128
NO_PROXY=localhost,127.0.0.1,db,nexus,keycloak,api-go,web,nginx,.internal.example.com
```

Клиенты реестров используют эти значения **явно**, а не полагаются на переменные окружения
процесса (`app/core/http.py::build_client`, `trust_env=False`): для каждого хоста из `NO_PROXY`
монтируется прямой транспорт без прокси, для остальных — транспорт с прокси. Это гарантирует
одинаковое поведение вне зависимости от того, как настроено окружение контейнера.

Записи `NO_PROXY`, которые httpx не умеет выразить паттерном (CIDR-подсети, IPv6, `host:port`),
пропускаются с предупреждением в лог — обычных доменных имён и `*.domain` это не касается.

Все внешние вызовы — с таймаутами (`HTTP_TIMEOUT_SECONDS`), ретраями с экспоненциальной паузой
(`HTTP_RETRIES`) и circuit breaker на сервис (`CIRCUIT_BREAKER_FAIL_MAX`,
`CIRCUIT_BREAKER_RESET_SECONDS`) — см. `app/core/http.py`.
