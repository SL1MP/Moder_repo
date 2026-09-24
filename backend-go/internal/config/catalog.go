package config

import (
	"strings"
	"time"
)

// Каталог настроек для экрана «Настройка». Порт settings_catalog из
// backend/app/core/config.py.
//
// Экран показывает действующие значения ВМЕСТЕ С ИМЕНЕМ ПЕРЕМЕННОЙ. Это не
// украшение: администратор смотрит сюда, чтобы понять, почему сервис ведёт
// себя не так, как он ожидал, и ответ «QUARANTINE_DAYS = 14» закрывает вопрос
// за секунду, а «карантин: 14 дней» оставляет искать, где это правится.
//
// Секреты показываются как «задано»/«не задано». Значения не показываются
// никогда: экран открыт всем ролям — по составу настроек видно, как устроен
// контур, но не чем он защищён.

// Setting — одна настройка для выдачи.
type Setting struct {
	Env         string `json:"env"`
	Section     string `json:"section"`
	Description string `json:"description"`
	Value       any    `json:"value"`
	// Secret — значение скрыто. Поле нужно интерфейсу, чтобы показать такие
	// строки иначе, а не выводить слово «задано» как обычное значение.
	Secret bool `json:"secret"`
}

// Catalog — действующие настройки, по разделам в порядке объявления.
func (c *Config) Catalog() []Setting {
	secret := func(value string) any {
		if strings.TrimSpace(value) != "" {
			return "задано"
		}
		return "не задано"
	}
	seconds := func(d time.Duration) any { return int(d.Seconds()) }

	return []Setting{
		{Env: "APP_ENV", Section: "Общие", Description: "dev | prod", Value: c.AppEnv},
		{Env: "APP_NAME", Section: "Общие", Description: "Заголовок в интерфейсе", Value: c.AppName},

		{Env: "QUARANTINE_DAYS", Section: "Пороги",
			Description: "Возраст версии, младше которого пакет ждёт карантина", Value: c.QuarantineDays},
		{Env: "VULN_MAX_SCORE", Section: "Пороги",
			Description: "Балл уязвимости, выше которого пакет уходит DevSecOps", Value: c.VulnMaxScore},

		{Env: "ARTIFACT_STORE", Section: "Артефактори",
			Description: "nexus | generic — у них разные протоколы выгрузки", Value: c.ArtifactStore},
		{Env: "ARTIFACT_BASE_URL", Section: "Артефактори",
			Description: "Адрес артефактори", Value: c.ArtifactBaseURL},
		{Env: "ARTIFACT_USER", Section: "Артефактори",
			Description: "Учётная запись для публикации", Value: c.ArtifactUser},
		{Env: "ARTIFACT_TOKEN", Section: "Артефактори",
			Description: "Токен или пароль", Value: secret(c.ArtifactToken), Secret: true},
		{Env: "ARTIFACT_REPO_STAGING", Section: "Артефактори",
			Description: "Промежуточная зона: где лежит пакет во время проверок",
			Value:       c.ArtifactRepoStaging},
		{Env: "ARTIFACT_REPO_REPORTS", Section: "Артефактори",
			Description: "Репозиторий отчётов сканирования", Value: c.ArtifactRepoReports},
		{Env: "ARTIFACT_REPO_OSV", Section: "Артефактори",
			Description: "raw-репозиторий со снапшотами OSV", Value: c.ArtifactRepoOSV},
		{Env: "ARTIFACT_DRY_RUN", Section: "Артефактори",
			Description: "Не публиковать по-настоящему (конвейер выполняется как есть)",
			Value:       c.ArtifactDryRun},

		{Env: "SANDBOX_ENABLED", Section: "Песочница",
			Description: "Шаг динамического анализа", Value: c.SandboxEnabled},
		{Env: "SANDBOX_URL", Section: "Песочница",
			Description: "Адрес песочницы", Value: c.SandboxURL},
		{Env: "SANDBOX_TOKEN", Section: "Песочница",
			Description: "Ключ API (он же SEC_TOKEN)", Value: secret(c.SandboxToken), Secret: true},
		{Env: "SANDBOX_TIMEOUT_SECONDS", Section: "Песочница",
			Description: "Потолок на один запрос", Value: seconds(c.SandboxTimeout)},
		{Env: "SANDBOX_INSECURE_TLS", Section: "Песочница",
			Description: "Принимать самоподписанный сертификат", Value: c.SandboxInsecureTLS},

		{Env: "OSV_DB_SOURCE", Section: "Уязвимости",
			Description: "Откуда берётся снапшот: artifactory | http | file", Value: c.OSVDBSource},
		{Env: "OSV_SNAPSHOT_PATH", Section: "Уязвимости",
			Description: "Путь к снапшоту внутри ARTIFACT_REPO_OSV", Value: c.OSVSnapshotPath},
		{Env: "OSV_DB_URL", Section: "Уязвимости",
			Description: "Адрес снапшота при OSV_DB_SOURCE=http", Value: c.OSVDBURL},
		{Env: "OSV_DB_FILE", Section: "Уязвимости",
			Description: "Путь к файлу при OSV_DB_SOURCE=file", Value: c.OSVDBFile},
		{Env: "OSV_SYNC_INTERVAL_SECONDS", Section: "Уязвимости",
			Description: "Как часто проверять, не появился ли новый снапшот",
			Value:       seconds(c.OSVSyncInterval)},
		{Env: "OSV_MAX_STALENESS_DAYS", Section: "Уязвимости",
			Description: "Возраст снапшота, после которого нет автоодобрения",
			Value:       c.OSVMaxStalenessDays},

		{Env: "BLACKLIST_FILE", Section: "Политики",
			Description: "Файл правил запрета", Value: c.BlacklistFile},
		{Env: "ALLOWED_LICENSES_FILE", Section: "Политики",
			Description: "Справочник лицензий", Value: c.AllowedLicensesFile},

		{Env: "OIDC_ISSUER", Section: "Доступ",
			Description: "Issuer OIDC (Keycloak)", Value: c.OIDCIssuer},
		{Env: "OIDC_CLIENT_ID", Section: "Доступ", Description: "client_id SPA", Value: c.OIDCClientID},
		{Env: "ROLE_MAPPING_ADMIN", Section: "Доступ",
			Description: "Группа каталога → роль admin", Value: c.RoleMappingAdmin},
		{Env: "ROLE_MAPPING_DEVSECOPS", Section: "Доступ",
			Description: "Группа каталога → роль devsecops", Value: c.RoleMappingDevSecOps},
		{Env: "ROLE_MAPPING_LEGAL", Section: "Доступ",
			Description: "Группа каталога → роль legal", Value: c.RoleMappingLegal},
		{Env: "ROLE_MAPPING_DEVELOPER", Section: "Доступ",
			Description: "Группа каталога → роль developer", Value: c.RoleMappingDeveloper},
		{Env: "LOCAL_AUTH_ENABLED", Section: "Доступ",
			Description: "Вход логин/пароль для сервисных учёток (в prod false)",
			Value:       c.LocalAuthEnabled},
		{Env: "LOCAL_AUTH_SECRET", Section: "Доступ",
			Description: "Ключ подписи локальных токенов",
			Value:       secret(c.LocalAuthSecret), Secret: true},

		{Env: "GITLAB_URL", Section: "GitLab",
			Description: "Базовый адрес GitLab (только чтение)", Value: c.GitlabURL},
		{Env: "GITLAB_OAUTH_CLIENT_ID", Section: "GitLab",
			Description: "OAuth client_id", Value: c.GitlabOAuthClientID},

		{Env: "MAX_UPLOAD_SIZE_BYTES", Section: "Лимиты",
			Description: "Максимальный размер файла зависимостей", Value: c.MaxUploadSizeBytes},
		{Env: "MAX_PACKAGES_PER_REQUEST", Section: "Лимиты",
			Description: "Максимум пакетов в заявке", Value: c.MaxPackagesPerRequest},
		{Env: "MAX_ARTIFACT_SIZE_BYTES", Section: "Лимиты",
			Description: "Максимальный размер артефакта", Value: c.MaxArtifactSizeBytes},
		{Env: "MAX_DOCKER_ARTIFACT_SIZE_BYTES", Section: "Лимиты",
			Description: "Максимальный суммарный размер multi-platform Docker-образа",
			Value:       c.MaxDockerArtifactSizeBytes},
		{Env: "RATE_LIMIT_REQUESTS_PER_MINUTE", Section: "Лимиты",
			Description: "Запросов в минуту на пользователя (0 — без ограничения)",
			Value:       c.RateLimitPerMinute},
		{Env: "COMMENT_EDIT_WINDOW_MINUTES", Section: "Лимиты",
			Description: "Окно правки комментария без пометки «изменено»",
			Value:       int(c.CommentEditWindow.Minutes())},

		{Env: "PIPELINE_WATCHDOG_ENABLED", Section: "Надёжность",
			Description: "Сторож подхватывает пакеты, зависшие в очереди",
			Value:       c.PipelineWatchdogEnabled},
		{Env: "PIPELINE_WATCHDOG_INTERVAL_SECONDS", Section: "Надёжность",
			Description: "Как часто сторож просматривает очередь",
			Value:       seconds(c.PipelineWatchdogInterval)},
		{Env: "PIPELINE_STUCK_AFTER_SECONDS", Section: "Надёжность",
			Description: "Через сколько пакет в очереди считается зависшим",
			Value:       seconds(c.PipelineStuckAfter)},
		{Env: "MAINTENANCE_ENABLED", Section: "Надёжность",
			Description: "Регламентные задачи воркера (карантин, уборка, снапшот)",
			Value:       c.MaintenanceEnabled},
		{Env: "STAGING_CLEANUP_INTERVAL_SECONDS", Section: "Надёжность",
			Description: "Как часто убирается промежуточная зона",
			Value:       seconds(c.StagingCleanupInterval)},
		{Env: "STAGING_ORPHAN_TTL_HOURS", Section: "Надёжность",
			Description: "Через сколько часов файл в промежуточной зоне считается брошенным",
			Value:       int(c.StagingOrphanTTL.Hours())},
		{Env: "REGISTRY_RETRY_ATTEMPTS", Section: "Надёжность",
			Description: "Попыток на один запрос к реестру", Value: c.RegistryRetryAttempts},
		{Env: "REGISTRY_BREAKER_THRESHOLD", Section: "Надёжность",
			Description: "Неудач подряд, после которых реестр перестаёт опрашиваться",
			Value:       c.RegistryBreakerThreshold},
	}
}

// CatalogSections — разделы каталога в порядке появления. Интерфейс группирует
// настройки по ним, и порядок обхода map в Go случаен: без явного списка
// разделы прыгали бы от запроса к запросу.
func (c *Config) CatalogSections() []string {
	seen := map[string]bool{}
	var out []string
	for _, setting := range c.Catalog() {
		if !seen[setting.Section] {
			seen[setting.Section] = true
			out = append(out, setting.Section)
		}
	}
	return out
}
