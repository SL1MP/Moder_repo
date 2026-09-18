// Package config читает конфигурацию сервиса из переменных окружения.
//
// Паттерн — как в sentrix (internal/config): Load собирает ВСЕ ошибки валидации
// разом через errors.Join, не падает на первой. В Python-версии это давалось
// бесплатно pydantic_settings; в Go так само по себе не происходит — нужно
// явно копить []error, см. docs/development-standards.md.
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"moderation/internal/domain"
)

// Config — конфигурация сервиса. Список переменных растёт по мере переноса
// возможностей из backend/app/core/config.py (см. docs/migration-to-go.md) —
// в этой ревизии есть только то, что нужно для каркаса (HTTP + подключение к БД).
type Config struct {
	AppEnv      string // dev | prod — влияет на строгость проверок, как в Python-версии
	AppName     string // заголовок в UI, отдаётся SPA в /auth/config
	ListenAddr  string
	DatabaseURL string

	// Хранилище отчётов и артефактов (карантинная зона). Пустой S3Endpoint —
	// хранилище не настроено: сервис поднимается, но выдача отчётов отключена.
	// Падать на старте из-за отчётов нельзя: health должен отвечать.
	S3Endpoint  string
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string
	S3Region    string
	// S3VirtualHost — адресация bucket.endpoint/key вместо endpoint/bucket/key.
	//
	// По умолчанию false (path-style): так работают MinIO и SeaweedFS, то есть
	// то, что поднимается рядом в compose. Внешние хранилища — в том числе
	// сертифицированные — часто требуют именно virtual-host, и без этой
	// настройки подключить их было нельзя: клиент умел оба стиля, но выбрать
	// было нечем.
	S3VirtualHost bool

	// Файлы политик. Те же, что читает python-версия, и монтируются они тем
	// же томом (./config:/config:ro): расхождение в том, какая лицензия
	// разрешена и какой пакет запрещён, недопустимо.
	BlacklistFile       string
	AllowedLicensesFile string

	// Сканеры содержимого. Имена переменных те же, что у python-версии
	// (см. .env.example): обе версии читают один .env, и расхождение в именах
	// означало бы, что шаг выключен в одной и включён в другой.
	BannerScanEnabled bool
	BannerRulesFile   string
	BannerScanBin     string
	BannerScanTimeout time.Duration
	SASTEnabled       bool
	SASTScannerBin    string
	SASTRules         string
	SASTTimeout       time.Duration
	SASTMinSeverity   string

	// Пороги конвейера. Значения по умолчанию — те же, что у python-версии
	// (backend/app/core/config.py): обе версии выносят вердикт по одному
	// пакету, и разные пороги означали бы разный вердикт при одном .env.
	QuarantineDays      int
	VulnMaxScore        float64
	OSVMaxStalenessDays int

	// Артефактори: адрес и целевые репозитории. Нужны, чтобы отдавать команду
	// установки одобренного пакета — её показывает карточка пакета и карточка
	// заявки.
	ArtifactBaseURL   string
	ArtifactRepoPyPI  string
	ArtifactRepoNpm   string
	ArtifactRepoGo    string
	ArtifactRepoNuGet string

	// Реестры пакетных менеджеров.
	RegistryPyPIURL  string
	RegistryNpmURL   string
	RegistryGoProxy  string
	RegistryNuGetURL string

	// Наблюдатель сканирования: сам находит пакеты без отчётов и прогоняет по
	// ним сканеры. Конструкция переходного периода — пока заявки ведёт
	// python-конвейер, а отчёты умеет делать только Go.
	ScanWatcherEnabled  bool
	ScanWatcherInterval time.Duration
	ScanWatcherBatch    int
	// ScanWatcherItemTimeout — потолок на один пакет. Прогон включает
	// перекачивание артефакта из внешнего реестра, поэтому запас нужен
	// большой, но не бесконечный: зависший пакет не должен держать пачку.
	ScanWatcherItemTimeout time.Duration

	// Доступ. OIDCIssuer — адрес, по которому К НЕМУ ходит сервис (внутренний,
	// http://keycloak:8080/...), OIDCPublicIssuer — адрес, по которому к нему
	// ходит браузер. Keycloak кладёт в claim `iss` тот адрес, по которому к
	// нему обратились, поэтому `iss` токена от SPA не совпадёт с внутренним —
	// принимаем оба, подпись при этом одна и та же.
	OIDCIssuer       string
	OIDCPublicIssuer string
	OIDCClientID     string

	// Группы каталога, дающие роль сервиса. Права проверяются в API, а не
	// только в UI.
	RoleMappingAdmin     string
	RoleMappingDevSecOps string
	RoleMappingLegal     string
	RoleMappingDeveloper string

	// Fallback-вход логин/пароль — только сервисные учётки, в prod выключен.
	LocalAuthEnabled  bool
	LocalAuthSecret   string
	LocalAuthTokenTTL time.Duration

	// GitLab здесь только для флага gitlab_enabled в /auth/config: сами
	// маршруты GitLab пока ведёт python-версия.
	GitlabURL           string
	GitlabOAuthClientID string

	// Артефактори — учётные данные для публикации и режим «без записи».
	// ArtifactStore — тип артефактори: nexus (по умолчанию) или generic.
	// У них разные протоколы выгрузки, и выбор не косметический: PUT в Nexus
	// отвечает 405 на каждом пакете.
	ArtifactStore    string
	ArtifactAuthType string
	ArtifactUser     string
	ArtifactToken    string
	ArtifactDryRun   bool

	// Каталог с распакованным снапшотом базы OSV.
	OSVLocalDBPath string

	// Конвейер и очередь. PipelineStuckAfter — через сколько молчания пакет
	// считается зависшим; брошенным прогон признаётся втрое позже (столько же,
	// сколько у python-версии: STALE_RUNNING_FACTOR = 3).
	PipelineStuckAfter time.Duration

	// Сторож очереди в процессе API: подбирает пакеты, которые не забрал
	// выделенный воркер. Включён по умолчанию — выключенный сторож означает,
	// что при мёртвом воркере пакет ждёт вечно.
	PipelineWatchdogEnabled  bool
	PipelineWatchdogInterval time.Duration

	// Окно, в течение которого правка сообщения не помечается как «изменено».
	CommentEditWindow time.Duration

	// Лимиты.
	MaxArtifactSizeBytes  int64
	MaxUploadSizeBytes    int64
	MaxPackagesPerRequest int

	// Раскрытие транзитивных зависимостей. Пределы здесь, а не в коде,
	// потому что их приходится подбирать под свою экосистему: глубина 3 по
	// npm — это сотни пакетов, по nuget — единицы.
	ResolveMaxDepth        int
	ResolveMaxPackages     int
	ResolveIncludeOptional bool
	ResolveConcurrency     int
	ScanMaxUnpackedBytes   int64
	ScanMaxFiles           int
}

// Load читает конфигурацию через getenv (не os.Getenv напрямую — тестируемость,
// тот же приём, что в sentrix).
func Load(getenv func(string) string) (*Config, error) {
	var errs []error

	cfg := &Config{
		AppEnv:      valueOr(getenv("APP_ENV"), "dev"),
		AppName:     valueOr(getenv("APP_NAME"), "Модерация пакетов"),
		ListenAddr:  valueOr(getenv("LISTEN_ADDR"), ":8000"),
		DatabaseURL: getenv("DATABASE_URL"),
		S3Endpoint:  getenv("S3_ENDPOINT"),
		S3Bucket:    valueOr(getenv("S3_BUCKET"), "moderation-artifacts"),
		S3AccessKey: getenv("S3_ACCESS_KEY"),
		S3SecretKey: getenv("S3_SECRET_KEY"),
		S3Region:    valueOr(getenv("S3_REGION"), "us-east-1"),
		// Значение по умолчанию false: см. комментарий к полю.
		S3VirtualHost: boolOr(getenv("S3_VIRTUAL_HOST"), false),

		BlacklistFile:       valueOr(getenv("BLACKLIST_FILE"), "/config/blacklist.yml"),
		AllowedLicensesFile: valueOr(getenv("ALLOWED_LICENSES_FILE"), "/config/licenses.yml"),

		BannerScanEnabled: boolOr(getenv("BANNER_SCAN_ENABLED"), true),
		BannerRulesFile:   valueOr(getenv("BANNER_RULES_FILE"), "/config/rules.yar"),
		BannerScanBin:     valueOr(getenv("BANNER_SCANNER_BIN"), "yara"),
		BannerScanTimeout: secondsOr(getenv("BANNER_SCAN_TOTAL_TIMEOUT_SECONDS"), 300),
		SASTEnabled:       boolOr(getenv("SAST_ENABLED"), true),
		SASTScannerBin:    valueOr(getenv("SAST_SCANNER_BIN"), "semgrep"),
		SASTRules:         valueOr(getenv("SAST_RULES"), "p/default"),
		SASTTimeout:       secondsOr(getenv("SAST_TIMEOUT_SECONDS"), 300),
		SASTMinSeverity:   valueOr(getenv("SAST_MIN_SEVERITY"), "high"),

		QuarantineDays:      intOr(getenv("QUARANTINE_DAYS"), 14),
		VulnMaxScore:        floatOr(getenv("VULN_MAX_SCORE"), 80),
		OSVMaxStalenessDays: intOr(getenv("OSV_MAX_STALENESS_DAYS"), 3),

		ArtifactBaseURL:   valueOr(getenv("ARTIFACT_BASE_URL"), "http://nexus:8081"),
		ArtifactRepoPyPI:  valueOr(getenv("ARTIFACT_REPO_PYPI"), "pypi-internal"),
		ArtifactRepoNpm:   valueOr(getenv("ARTIFACT_REPO_NPM"), "npm-internal"),
		ArtifactRepoGo:    valueOr(getenv("ARTIFACT_REPO_GO"), "go-internal"),
		ArtifactRepoNuGet: valueOr(getenv("ARTIFACT_REPO_NUGET"), "nuget-internal"),

		RegistryPyPIURL:  valueOr(getenv("REGISTRY_PYPI_URL"), "https://pypi.org"),
		RegistryNpmURL:   valueOr(getenv("REGISTRY_NPM_URL"), "https://registry.npmjs.org"),
		RegistryGoProxy:  valueOr(getenv("REGISTRY_GO_PROXY"), "https://proxy.golang.org"),
		RegistryNuGetURL: valueOr(getenv("REGISTRY_NUGET_URL"), "https://api.nuget.org"),

		ScanWatcherEnabled:     boolOr(getenv("SCAN_WATCHER_ENABLED"), true),
		ScanWatcherInterval:    secondsOr(getenv("SCAN_WATCHER_INTERVAL_SECONDS"), 60),
		ScanWatcherBatch:       intOr(getenv("SCAN_WATCHER_BATCH"), 10),
		ScanWatcherItemTimeout: secondsOr(getenv("SCAN_WATCHER_ITEM_TIMEOUT_SECONDS"), 20*60),

		OIDCIssuer:       strings.TrimRight(strings.TrimSpace(getenv("OIDC_ISSUER")), "/"),
		OIDCPublicIssuer: strings.TrimRight(strings.TrimSpace(getenv("OIDC_PUBLIC_ISSUER")), "/"),
		OIDCClientID:     valueOr(getenv("OIDC_CLIENT_ID"), "moderation-web"),

		RoleMappingAdmin:     valueOr(getenv("ROLE_MAPPING_ADMIN"), "moderation-admin"),
		RoleMappingDevSecOps: valueOr(getenv("ROLE_MAPPING_DEVSECOPS"), "moderation-devsecops"),
		RoleMappingLegal:     valueOr(getenv("ROLE_MAPPING_LEGAL"), "moderation-legal"),
		RoleMappingDeveloper: valueOr(getenv("ROLE_MAPPING_DEVELOPER"), "moderation-developer"),

		LocalAuthEnabled:  boolOr(getenv("LOCAL_AUTH_ENABLED"), false),
		LocalAuthSecret:   valueOr(getenv("LOCAL_AUTH_SECRET"), "change-me-in-prod"),
		LocalAuthTokenTTL: time.Duration(intOr(getenv("LOCAL_AUTH_TOKEN_TTL_MINUTES"), 480)) * time.Minute,

		GitlabURL:           getenv("GITLAB_URL"),
		GitlabOAuthClientID: getenv("GITLAB_OAUTH_CLIENT_ID"),

		ArtifactStore:    valueOr(getenv("ARTIFACT_STORE"), "nexus"),
		ArtifactAuthType: valueOr(getenv("ARTIFACT_AUTH_TYPE"), "basic"),
		ArtifactUser:     getenv("ARTIFACT_USER"),
		ArtifactToken:    getenv("ARTIFACT_TOKEN"),
		ArtifactDryRun:   boolOr(getenv("ARTIFACT_DRY_RUN"), false),

		OSVLocalDBPath: valueOr(getenv("OSV_LOCAL_DB_PATH"), "/var/lib/osv-db"),

		PipelineStuckAfter:       secondsOr(getenv("PIPELINE_STUCK_AFTER_SECONDS"), 120),
		PipelineWatchdogEnabled:  boolOr(getenv("PIPELINE_WATCHDOG_ENABLED"), true),
		PipelineWatchdogInterval: secondsOr(getenv("PIPELINE_WATCHDOG_INTERVAL_SECONDS"), 30),

		CommentEditWindow: time.Duration(intOr(getenv("COMMENT_EDIT_WINDOW_MINUTES"), 15)) * time.Minute,

		MaxArtifactSizeBytes:  bytesOr(getenv("MAX_ARTIFACT_SIZE_BYTES"), 500*1024*1024),
		MaxUploadSizeBytes:    bytesOr(getenv("MAX_UPLOAD_SIZE_BYTES"), 5*1024*1024),
		MaxPackagesPerRequest: intOr(getenv("MAX_PACKAGES_PER_REQUEST"), 200),

		ResolveMaxDepth:        intOr(getenv("RESOLVE_MAX_DEPTH"), 3),
		ResolveMaxPackages:     intOr(getenv("RESOLVE_MAX_PACKAGES"), 200),
		ResolveIncludeOptional: boolOr(getenv("RESOLVE_INCLUDE_OPTIONAL"), false),
		ResolveConcurrency:     intOr(getenv("RESOLVE_CONCURRENCY"), 8),
		ScanMaxUnpackedBytes:   bytesOr(getenv("SCAN_MAX_UNPACKED_BYTES"), 512<<20),
		ScanMaxFiles:           intOr(getenv("SCAN_MAX_FILES"), 20000),
	}

	if cfg.AppEnv != "dev" && cfg.AppEnv != "prod" {
		errs = append(errs, fmt.Errorf("APP_ENV: недопустимое значение %q, ожидается dev или prod", cfg.AppEnv))
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		errs = append(errs, errors.New("DATABASE_URL: не задан — подключение к Postgres невозможно"))
	}
	// Хранилище задано наполовину — это почти наверняка опечатка в .env, и
	// молча работать без отчётов здесь хуже, чем сказать об этом на старте.
	if strings.TrimSpace(cfg.S3Endpoint) != "" {
		if strings.TrimSpace(cfg.S3AccessKey) == "" || strings.TrimSpace(cfg.S3SecretKey) == "" {
			errs = append(errs, errors.New(
				"S3_ACCESS_KEY/S3_SECRET_KEY: не заданы при заданном S3_ENDPOINT — хранилище отчётов не настроится"))
		}
	}

	// Порог SAST проверяем явно: опечатка в нём ("hight") молча превратилась бы
	// в "medium" и тихо изменила бы то, какие находки блокируют публикацию.
	if !domain.Contains([]string{"info", "low", "medium", "high", "critical"}, cfg.SASTMinSeverity) {
		errs = append(errs, fmt.Errorf(
			"SAST_MIN_SEVERITY: недопустимое значение %q, ожидается info|low|medium|high|critical",
			cfg.SASTMinSeverity))
	}

	// Тип артефактори проверяем на старте: опечатка ("nexsus") иначе всплыла
	// бы только на шаге публикации — после того, как пакет уже скачали и
	// просканировали, и у людей уже спросили решение.
	if !domain.Contains([]string{"nexus", "generic"}, strings.ToLower(cfg.ArtifactStore)) {
		errs = append(errs, fmt.Errorf(
			"ARTIFACT_STORE: недопустимое значение %q, ожидается nexus|generic", cfg.ArtifactStore))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("конфигурация невалидна (%d ошибок): %w", len(errs), errors.Join(errs...))
	}
	return cfg, nil
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// valueOr и родственники: пустая переменная — это «не задано», а не «пусто».
// Python-версия получала это бесплатно от pydantic_settings, в Go нужно явно.

func boolOr(v string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func intOr(v string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func bytesOr(v string, fallback int64) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func secondsOr(v string, fallback int) time.Duration {
	return time.Duration(intOr(v, fallback)) * time.Second
}

func floatOr(v string, fallback float64) float64 {
	n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

// --------------------------------------------------------------------------- доступ

// BrowserIssuer — адрес издателя для браузера. Порт config.browser_issuer.
func (c *Config) BrowserIssuer() string {
	if c.OIDCPublicIssuer != "" {
		return c.OIDCPublicIssuer
	}
	return c.OIDCIssuer
}

// AcceptedIssuers — issuer'ы, которым доверяем при проверке токена.
//
// Порт config.accepted_issuers. Их два, потому что Keycloak подставляет в
// claim `iss` тот адрес, по которому к нему обратились: браузер ходит по
// внешнему, сервис берёт JWKS по внутреннему. Подпись одна и та же.
func (c *Config) AcceptedIssuers() []string {
	var out []string
	for _, iss := range []string{c.OIDCIssuer, c.OIDCPublicIssuer} {
		if iss == "" || domain.Contains(out, iss) {
			continue
		}
		out = append(out, iss)
	}
	return out
}

// ArtifactRepo — целевой репозиторий артефактори для менеджера. Пустая
// строка — менеджер неизвестен.
func (c *Config) ArtifactRepo(manager string) string {
	switch manager {
	case "pypi":
		return c.ArtifactRepoPyPI
	case "npm":
		return c.ArtifactRepoNpm
	case "go":
		return c.ArtifactRepoGo
	case "nuget":
		return c.ArtifactRepoNuGet
	}
	return ""
}

// RoleForGroup — роль сервиса по группе каталога. Пустая строка — группа не
// наша. Порт config.role_for_group.
func (c *Config) RoleForGroup(group string) string {
	switch group {
	case c.RoleMappingAdmin:
		return "admin"
	case c.RoleMappingDevSecOps:
		return "devsecops"
	case c.RoleMappingLegal:
		return "legal"
	case c.RoleMappingDeveloper:
		return "developer"
	}
	return ""
}
