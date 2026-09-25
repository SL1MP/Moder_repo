"""Конфигурация сервиса. Единственный источник — переменные окружения (.env).

UI-редактирования настроек нет: экран «Настройка» читает значения отсюда вместе
с именем переменной (см. :func:`settings_catalog`).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # общее
    app_env: Literal["dev", "prod", "test"] = "dev"
    app_name: str = "Модерация пакетов"
    log_level: str = "INFO"
    public_base_url: str = "http://localhost:8080"

    # БД
    postgres_host: str = "db"
    postgres_port: int = 5432
    postgres_db: str = "moderation"
    postgres_user: str = "moderation"
    postgres_password: str = "moderation"
    database_url: str = ""

    # Celery
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/0"
    celery_result_backend: str = "redis://redis:6379/1"
    # Выполнять задачи синхронно в вызывающем процессе (тесты, отладка без worker).
    celery_task_always_eager: bool = False

    # надёжность конвейера: пакет не должен ждать ручного запуска команды
    worker_heartbeat_interval_seconds: int = 15
    worker_heartbeat_ttl_seconds: int = 60
    pipeline_watchdog_enabled: bool = True
    pipeline_watchdog_interval_seconds: int = 30
    pipeline_stuck_after_seconds: int = 120

    # политики
    quarantine_days: int = 14
    vuln_max_score: float = 80.0
    blacklist_file: str = "/config/blacklist.yml"
    allowed_licenses_file: str = "/config/licenses.yml"

    # реестры и сеть
    registry_pypi_url: str = "https://pypi.org"
    registry_npm_url: str = "https://registry.npmjs.org"
    registry_go_proxy: str = "https://proxy.golang.org"
    registry_nuget_url: str = "https://api.nuget.org"
    http_proxy: str = ""
    https_proxy: str = ""
    no_proxy: str = "localhost,127.0.0.1,db,redis,minio,nexus,keycloak"

    # S3 / MinIO
    s3_endpoint: str = "http://minio:9000"
    s3_bucket: str = "packages"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_region: str = "us-east-1"
    s3_secure: bool = False
    s3_orphan_ttl_hours: int = 24

    # артефактори
    artifact_store: Literal["nexus", "generic"] = "nexus"
    artifact_base_url: str = "http://nexus:8081"
    artifact_user: str = "admin"
    artifact_token: str = ""
    artifact_repo_pypi: str = "pypi-internal"
    artifact_repo_npm: str = "npm-internal"
    artifact_repo_go: str = "go-internal"
    artifact_repo_nuget: str = "nuget-internal"
    artifact_repo_osv: str = "osv-snapshots"
    artifact_auth_type: Literal["basic", "token"] = "basic"
    artifact_path_template_pypi: str = "{repo}/{name}/{filename}"
    artifact_path_template_npm: str = "{repo}/{name}/-/{filename}"
    artifact_path_template_go: str = "{repo}/{name}/@v/{filename}"
    artifact_path_template_nuget: str = "{repo}/{name}/{version}/{filename}"
    # Прогоняет весь конвейер по-настоящему (download/vuln_scan/banner_scan/...),
    # но не пишет байты в целевой артефактори на шаге publish — только проверяет
    # достижимость/авторизацию (HEAD) и логирует, что было бы опубликовано.
    # Нужно для проверки сервиса реальными кредами от продового Artifactory без
    # риска записи в него, см. docs/testing.md, "Тесты не пишут в целевой Artifactory".
    artifact_dry_run: bool = False

    # OSV
    osv_source: Literal["snapshot", "api"] = "snapshot"
    osv_snapshot_path: str = "osv/latest/osv-all.zip"
    osv_local_db_path: str = "/var/lib/osv-db/current"
    osv_sync_cron: str = "0 4 * * *"
    osv_max_staleness_days: int = 3
    osv_api_url: str = "https://api.osv.dev"
    osv_scanner_bin: str = "osv-scanner"

    # сканирование содержимого пакета
    # Политические баннеры (протестварь): правила те же, что в CI-конвейерах
    # модерации, чтобы вердикт сервиса и CI не расходился.
    banner_scan_enabled: bool = True
    banner_rules_file: str = "/config/rules.yar"
    banner_scan_timeout_seconds: int = 10
    # SAST. Бинарь внешний (как osv-scanner): если его нет, шаг не пропускает
    # пакет молча, а отдаёт решение DevSecOps.
    sast_enabled: bool = True
    sast_scanner_bin: str = "semgrep"
    sast_rules: str = "p/default"
    sast_timeout_seconds: int = 300
    # Начиная с какой серьёзности находка требует решения DevSecOps.
    sast_min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    # Границы распаковки артефакта перед сканированием (архивная бомба).
    scan_max_unpacked_bytes: int = 512 * 1024 * 1024
    scan_max_files: int = 20_000

    # доступ
    oidc_issuer: str = ""
    oidc_public_issuer: str = ""
    oidc_client_id: str = "moderation-web"
    oidc_client_secret: str = ""
    oidc_audience: str = "account"
    role_mapping_admin: str = "moderation-admin"
    role_mapping_devsecops: str = "moderation-devsecops"
    role_mapping_legal: str = "moderation-legal"
    role_mapping_developer: str = "moderation-developer"
    local_auth_enabled: bool = False
    local_auth_secret: str = "change-me-in-prod"
    local_auth_token_ttl_minutes: int = 480

    # GitLab
    gitlab_url: str = ""
    gitlab_oauth_client_id: str = ""
    gitlab_oauth_client_secret: str = ""
    gitlab_oauth_redirect_uri: str = ""
    fernet_key: str = ""

    # лимиты
    max_upload_size_bytes: int = 5 * 1024 * 1024
    max_packages_per_request: int = 200
    rate_limit_requests_per_minute: int = 30
    max_artifact_size_bytes: int = 500 * 1024 * 1024
    http_timeout_seconds: float = 30.0
    http_retries: int = 3
    circuit_breaker_fail_max: int = 5
    circuit_breaker_reset_seconds: int = 60
    comment_edit_window_minutes: int = 15

    @field_validator("vuln_max_score")
    @classmethod
    def _score_range(cls, v: float) -> float:
        if not 0 <= v <= 100:
            raise ValueError("VULN_MAX_SCORE должен быть в диапазоне 0..100")
        return v

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def browser_issuer(self) -> str:
        return self.oidc_public_issuer or self.oidc_issuer

    @property
    def accepted_issuers(self) -> tuple[str, ...]:
        """Issuer'ы, которым доверяем при проверке токена.

        Keycloak подставляет в claim `iss` тот адрес, по которому к нему обратились.
        Браузер ходит по внешнему адресу (`OIDC_PUBLIC_ISSUER`,
        например http://localhost:8081/realms/moderation), а API берёт JWKS по
        внутреннему (`OIDC_ISSUER`, http://keycloak:8080/realms/moderation) — значит
        `iss` в токене не совпадёт с внутренним адресом. Подпись при этом одна и та
        же, поэтому принимаем оба варианта.
        """
        issuers = [
            issuer.rstrip("/")
            for issuer in (self.oidc_issuer, self.oidc_public_issuer)
            if issuer
        ]
        return tuple(dict.fromkeys(issuers))

    def registry_url(self, manager: str) -> str:
        return {
            "pypi": self.registry_pypi_url,
            "npm": self.registry_npm_url,
            "go": self.registry_go_proxy,
            "nuget": self.registry_nuget_url,
        }[manager]

    def artifact_repo(self, manager: str) -> str:
        return {
            "pypi": self.artifact_repo_pypi,
            "npm": self.artifact_repo_npm,
            "go": self.artifact_repo_go,
            "nuget": self.artifact_repo_nuget,
        }[manager]

    def artifact_path_template(self, manager: str) -> str:
        return {
            "pypi": self.artifact_path_template_pypi,
            "npm": self.artifact_path_template_npm,
            "go": self.artifact_path_template_go,
            "nuget": self.artifact_path_template_nuget,
        }[manager]

    def role_for_group(self, group: str) -> str | None:
        mapping = {
            self.role_mapping_admin: "admin",
            self.role_mapping_devsecops: "devsecops",
            self.role_mapping_legal: "legal",
            self.role_mapping_developer: "developer",
        }
        return mapping.get(group)

    @property
    def proxies(self) -> dict[str, str]:
        """Явная карта прокси для httpx — не полагаемся на неявное чтение env."""
        mounts: dict[str, str] = {}
        if self.http_proxy:
            mounts["http://"] = self.http_proxy
        if self.https_proxy:
            mounts["https://"] = self.https_proxy
        return mounts

    @property
    def no_proxy_hosts(self) -> list[str]:
        return [h.strip() for h in self.no_proxy.split(",") if h.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Каталог настроек для экрана «Настройка» (только чтение).
# (env-имя, раздел, описание, скрывать значение)
SETTINGS_CATALOG: list[tuple[str, str, str, bool]] = [
    ("QUARANTINE_DAYS", "Политики", "Карантин: версия моложе N дней уходит на ожидание", False),
    ("VULN_MAX_SCORE", "Политики", "Порог уязвимости 0..100 (CVSS × 10), выше — fail", False),
    ("BLACKLIST_FILE", "Политики", "Файл правил blacklist", False),
    ("ALLOWED_LICENSES_FILE", "Политики", "Справочник разрешённых лицензий (SPDX)", False),
    ("REGISTRY_PYPI_URL", "Реестры", "Базовый URL реестра pypi", False),
    ("REGISTRY_NPM_URL", "Реестры", "Базовый URL реестра npm", False),
    ("REGISTRY_GO_PROXY", "Реестры", "Go module proxy", False),
    ("REGISTRY_NUGET_URL", "Реестры", "Базовый URL реестра nuget", False),
    ("HTTP_PROXY", "Сеть", "Корпоративный прокси для http", False),
    ("HTTPS_PROXY", "Сеть", "Корпоративный прокси для https", False),
    ("NO_PROXY", "Сеть", "Адреса в обход прокси (внутренние сервисы)", False),
    ("S3_ENDPOINT", "Временное хранилище", "Адрес MinIO/S3", False),
    ("S3_BUCKET", "Временное хранилище", "Бакет для карантинных архивов", False),
    ("S3_ACCESS_KEY", "Временное хранилище", "Ключ доступа S3", True),
    ("S3_SECRET_KEY", "Временное хранилище", "Секретный ключ S3", True),
    ("S3_ORPHAN_TTL_HOURS", "Временное хранилище", "TTL зависших объектов, часы", False),
    ("ARTIFACT_STORE", "Артефактори", "Реализация ArtifactStore: nexus | generic", False),
    ("ARTIFACT_BASE_URL", "Артефактори", "Базовый URL артефактори", False),
    ("ARTIFACT_USER", "Артефактори", "Пользователь артефактори", False),
    ("ARTIFACT_TOKEN", "Артефактори", "Токен/пароль артефактори", True),
    ("ARTIFACT_REPO_PYPI", "Артефактори", "hosted-репозиторий pypi", False),
    ("ARTIFACT_REPO_NPM", "Артефактори", "hosted-репозиторий npm", False),
    ("ARTIFACT_REPO_GO", "Артефактори", "hosted-репозиторий go", False),
    ("ARTIFACT_REPO_NUGET", "Артефактори", "hosted-репозиторий nuget", False),
    ("ARTIFACT_REPO_OSV", "Артефактори", "raw-репозиторий со снапшотами OSV", False),
    (
        "ARTIFACT_DRY_RUN",
        "Артефактори",
        "Не публиковать по-настоящему (весь конвейер выполняется как есть)",
        False,
    ),
    ("OSV_SOURCE", "Уязвимости", "snapshot (боевой) | api (только dev)", False),
    ("OSV_SNAPSHOT_PATH", "Уязвимости", "Путь к снапшоту внутри ARTIFACT_REPO_OSV", False),
    ("OSV_SYNC_CRON", "Уязвимости", "Расписание синхронизации снапшота", False),
    ("OSV_MAX_STALENESS_DAYS", "Уязвимости", "Максимальный возраст снапшота, дней", False),
    ("OIDC_ISSUER", "Доступ", "Issuer OIDC (Keycloak)", False),
    ("OIDC_CLIENT_ID", "Доступ", "client_id SPA", False),
    ("OIDC_CLIENT_SECRET", "Доступ", "client_secret", True),
    ("ROLE_MAPPING_ADMIN", "Доступ", "Группа каталога → роль admin", False),
    ("ROLE_MAPPING_DEVSECOPS", "Доступ", "Группа каталога → роль devsecops", False),
    ("ROLE_MAPPING_LEGAL", "Доступ", "Группа каталога → роль legal", False),
    ("ROLE_MAPPING_DEVELOPER", "Доступ", "Группа каталога → роль developer", False),
    ("LOCAL_AUTH_ENABLED", "Доступ", "Fallback-вход логин/пароль (в prod false)", False),
    ("GITLAB_URL", "GitLab", "Базовый URL GitLab (только чтение)", False),
    ("GITLAB_OAUTH_CLIENT_ID", "GitLab", "OAuth client_id", False),
    ("GITLAB_OAUTH_CLIENT_SECRET", "GitLab", "OAuth client_secret", True),
    ("FERNET_KEY", "GitLab", "Ключ шифрования refresh-токенов", True),
    ("MAX_UPLOAD_SIZE_BYTES", "Лимиты", "Максимальный размер файла зависимостей", False),
    ("MAX_PACKAGES_PER_REQUEST", "Лимиты", "Максимум пакетов в заявке", False),
    ("RATE_LIMIT_REQUESTS_PER_MINUTE", "Лимиты", "Запросов в минуту на пользователя", False),
    ("MAX_ARTIFACT_SIZE_BYTES", "Лимиты", "Максимальный размер артефакта", False),
    ("COMMENT_EDIT_WINDOW_MINUTES", "Лимиты", "Окно правки комментария без пометки", False),
    (
        "PIPELINE_WATCHDOG_ENABLED",
        "Надёжность",
        "Сторож подхватывает пакеты, зависшие в очереди",
        False,
    ),
    (
        "PIPELINE_WATCHDOG_INTERVAL_SECONDS",
        "Надёжность",
        "Как часто сторож просматривает очередь, секунд",
        False,
    ),
    (
        "PIPELINE_STUCK_AFTER_SECONDS",
        "Надёжность",
        "Через сколько секунд пакет в очереди считается зависшим",
        False,
    ),
    (
        "WORKER_HEARTBEAT_TTL_SECONDS",
        "Надёжность",
        "Без heartbeat дольше этого worker считается мёртвым",
        False,
    ),
]


def settings_catalog() -> list[dict[str, object]]:
    """Действующие значения настроек для экрана «Настройка» (read-only)."""
    s = get_settings()
    out: list[dict[str, object]] = []
    for env_name, section, description, secret in SETTINGS_CATALOG:
        value = getattr(s, env_name.lower(), None)
        if secret:
            shown: object = "задано" if value else "не задано"
        else:
            shown = value
        out.append(
            {
                "env": env_name,
                "section": section,
                "description": description,
                "value": shown,
                "secret": secret,
            }
        )
    return out
