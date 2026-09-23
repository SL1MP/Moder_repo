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

	// Хранилища сервиса — оба в артефактори, отдельного объектного хранилища
	// у сервиса больше нет (отказ от S3, решение пользователя).
	//
	// ArtifactRepoStaging — промежуточная зона: скачанный пакет лежит в ней,
	// пока идут проверки, и переезжает в репозиторий своего менеджера после
	// того, как все они пройдены. ArtifactRepoReports — отчёты сканирования,
	// живущие дольше самого артефакта.
	//
	// Оба обязаны быть репозиториями типа raw (generic у Artifactory): в них
	// кладутся файлы по произвольным путям, а не пакеты.
	ArtifactRepoStaging string
	ArtifactRepoReports string

	// Файлы политик. Те же, что читает python-версия, и монтируются они тем
	// же томом (./config:/config:ro): расхождение в том, какая лицензия
	// разрешена и какой пакет запрещён, недопустимо.
	BlacklistFile       string
	AllowedLicensesFile string

	// Песочница — шаг sandbox_scan. Артефакт целиком уходит во внешнюю
	// систему, та запускает его и возвращает вердикт (CLEAN / UNWANTED /
	// DANGEROUS). Имена переменных — те же, что в CI-шаблоне `.send_to_sandbox`
	// (SANDBOX_URL, SEC_TOKEN), чтобы один и тот же секрет не приходилось
	// заводить дважды под разными именами.
	SandboxEnabled bool
	SandboxURL     string
	SandboxToken   string
	// SandboxPriority — приоритет задачи в очереди песочницы; в CI-шаблоне 3.
	SandboxPriority int
	// SandboxShortResult — короткий ответ вместо полного (в CI — true).
	SandboxShortResult bool
	// SandboxTimeout — потолок на один запрос. Песочница запускает образец
	// по-настоящему, поэтому потолок минутный, а не секундный.
	SandboxTimeout time.Duration
	// SandboxInsecureTLS — принимать самоподписанный сертификат: это `curl -k`
	// из CI-шаблона. Отдельной настройкой, а не молча: выключенная проверка
	// сертификата обязана быть видимым решением, а не строчкой в скрипте.
	SandboxInsecureTLS bool

	// Сканеры содержимого СНЯТЫХ шагов (pipeline.RetiredSteps): политические
	// баннеры и SAST. Конвейер их не запускает — настройки оставлены вместе с
	// самими шагами, чтобы возврат в строй не требовал ещё и восстановления
	// конфигурации. Имена переменных те же, что у python-версии.
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
	ArtifactBaseURL string
	// ArtifactRepos — репозиторий на каждый менеджер, ключ — код менеджера.
	// Читается из ARTIFACT_REPO_{МЕНЕДЖЕР}, по умолчанию «{менеджер}-internal».
	//
	// Карта, а не поле на менеджер: менеджеров двенадцать, и каждый новый
	// требовал бы правки в четырёх местах (поле, чтение, switch, .env.example).
	// Ровно так уже разъезжались списки допустимых значений.
	ArtifactRepos map[string]string

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
	// Откуда берётся снапшот: репозиторий артефактори и путь внутри него.
	ArtifactRepoOSV string
	OSVSnapshotPath string
	// OSVSyncInterval — как часто воркер проверяет, не выложили ли новый
	// снапшот. Ноль и меньше — синхронизация выключена.
	OSVSyncInterval time.Duration

	// Конвейер и очередь. PipelineStuckAfter — через сколько молчания пакет
	// считается зависшим; брошенным прогон признаётся втрое позже (столько же,
	// сколько у python-версии: STALE_RUNNING_FACTOR = 3).
	PipelineStuckAfter time.Duration

	// Сторож очереди в процессе API: подбирает пакеты, которые не забрал
	// выделенный воркер. Включён по умолчанию — выключенный сторож означает,
	// что при мёртвом воркере пакет ждёт вечно.
	PipelineWatchdogEnabled  bool
	PipelineWatchdogInterval time.Duration

	// Регламентные задачи воркера. Без них карантин не снимается сам, а
	// временное хранилище растёт — и то и другое происходит молча.
	MaintenanceEnabled      bool
	QuarantineSweepInterval time.Duration
	S3CleanupInterval       time.Duration
	S3OrphanTTL             time.Duration

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
		AppEnv:              valueOr(getenv("APP_ENV"), "dev"),
		AppName:             valueOr(getenv("APP_NAME"), "Модерация пакетов"),
		ListenAddr:          valueOr(getenv("LISTEN_ADDR"), ":8000"),
		DatabaseURL:         getenv("DATABASE_URL"),
		ArtifactRepoStaging: valueOr(getenv("ARTIFACT_REPO_STAGING"), "moderation-staging"),
		ArtifactRepoReports: valueOr(getenv("ARTIFACT_REPO_REPORTS"), "moderation-reports"),

		BlacklistFile:       valueOr(getenv("BLACKLIST_FILE"), "/config/blacklist.yml"),
		AllowedLicensesFile: valueOr(getenv("ALLOWED_LICENSES_FILE"), "/config/licenses.yml"),

		// По умолчанию шаг включён ровно тогда, когда задан адрес песочницы.
		// Так набор настроек по умолчанию остаётся рабочим (иначе сервис не
		// поднимался бы без SANDBOX_URL), а явное SANDBOX_ENABLED=true без
		// адреса остаётся ошибкой — это уже не умолчание, а противоречие.
		SandboxEnabled:     boolOr(getenv("SANDBOX_ENABLED"), strings.TrimSpace(getenv("SANDBOX_URL")) != ""),
		SandboxURL:         strings.TrimRight(strings.TrimSpace(getenv("SANDBOX_URL")), "/"),
		SandboxToken:       valueOr(getenv("SANDBOX_TOKEN"), getenv("SEC_TOKEN")),
		SandboxPriority:    intOr(getenv("SANDBOX_PRIORITY"), 3),
		SandboxShortResult: boolOr(getenv("SANDBOX_SHORT_RESULT"), true),
		SandboxTimeout:     secondsOr(getenv("SANDBOX_TIMEOUT_SECONDS"), 900),
		SandboxInsecureTLS: boolOr(getenv("SANDBOX_INSECURE_TLS"), false),

		// Шаги сняты с конвейера: значения по умолчанию false, чтобы включённым
		// оказался только тот шаг, который явно включили обратно.
		BannerScanEnabled: boolOr(getenv("BANNER_SCAN_ENABLED"), false),
		BannerRulesFile:   valueOr(getenv("BANNER_RULES_FILE"), "/config/rules.yar"),
		BannerScanBin:     valueOr(getenv("BANNER_SCANNER_BIN"), "yara"),
		BannerScanTimeout: secondsOr(getenv("BANNER_SCAN_TOTAL_TIMEOUT_SECONDS"), 300),
		SASTEnabled:       boolOr(getenv("SAST_ENABLED"), false),
		SASTScannerBin:    valueOr(getenv("SAST_SCANNER_BIN"), "semgrep"),
		SASTRules:         valueOr(getenv("SAST_RULES"), "p/default"),
		SASTTimeout:       secondsOr(getenv("SAST_TIMEOUT_SECONDS"), 300),
		SASTMinSeverity:   valueOr(getenv("SAST_MIN_SEVERITY"), "high"),

		QuarantineDays:      intOr(getenv("QUARANTINE_DAYS"), 14),
		VulnMaxScore:        floatOr(getenv("VULN_MAX_SCORE"), 80),
		OSVMaxStalenessDays: intOr(getenv("OSV_MAX_STALENESS_DAYS"), 3),

		ArtifactBaseURL: valueOr(getenv("ARTIFACT_BASE_URL"), "http://nexus:8081"),
		ArtifactRepos:   artifactRepos(getenv),

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

		OSVLocalDBPath:  valueOr(getenv("OSV_LOCAL_DB_PATH"), "/var/lib/osv-db"),
		ArtifactRepoOSV: valueOr(getenv("ARTIFACT_REPO_OSV"), "osv-snapshots"),
		OSVSnapshotPath: valueOr(getenv("OSV_SNAPSHOT_PATH"), "osv/latest/osv-all.zip"),
		OSVSyncInterval: secondsOr(getenv("OSV_SYNC_INTERVAL_SECONDS"), 6*60*60),

		PipelineStuckAfter:       secondsOr(getenv("PIPELINE_STUCK_AFTER_SECONDS"), 120),
		PipelineWatchdogEnabled:  boolOr(getenv("PIPELINE_WATCHDOG_ENABLED"), true),
		PipelineWatchdogInterval: secondsOr(getenv("PIPELINE_WATCHDOG_INTERVAL_SECONDS"), 30),

		// Интервалы совпадают с расписанием python-версии (celery beat):
		// карантин — раз в 15 минут, уборка хранилища — раз в 2 часа.
		MaintenanceEnabled:      boolOr(getenv("MAINTENANCE_ENABLED"), true),
		QuarantineSweepInterval: secondsOr(getenv("QUARANTINE_SWEEP_INTERVAL_SECONDS"), 15*60),
		S3CleanupInterval:       secondsOr(getenv("S3_CLEANUP_INTERVAL_SECONDS"), 2*60*60),
		S3OrphanTTL:             time.Duration(intOr(getenv("S3_ORPHAN_TTL_HOURS"), 24)) * time.Hour,

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
	// Оба хранилища живут в артефактори, и пустое имя репозитория означало бы
	// запись в корень — то есть мусор вперемешку с пакетами.
	if strings.TrimSpace(cfg.ArtifactRepoStaging) == "" {
		errs = append(errs, errors.New(
			"ARTIFACT_REPO_STAGING: не задан — скачанному пакету негде лежать во время проверок"))
	}
	if strings.TrimSpace(cfg.ArtifactRepoReports) == "" {
		errs = append(errs, errors.New(
			"ARTIFACT_REPO_REPORTS: не задан — отчёты сканирования негде хранить"))
	}
	// Промежуточная зона и целевые репозитории обязаны различаться: иначе
	// непроверенный пакет лежал бы там же, откуда его ставят разработчики, —
	// то есть до всякой модерации был бы доступен для установки.
	for manager, repoName := range cfg.ArtifactRepos {
		if repoName == cfg.ArtifactRepoStaging {
			errs = append(errs, fmt.Errorf(
				"ARTIFACT_REPO_%s совпадает с ARTIFACT_REPO_STAGING (%q): непроверенный пакет "+
					"оказался бы в репозитории, из которого ставят разработчики",
				strings.ToUpper(manager), repoName))
		}
	}

	// Порог SAST проверяем явно: опечатка в нём ("hight") молча превратилась бы
	// в "medium" и тихо изменила бы то, какие находки блокируют публикацию.
	// Шаг снят с конвейера, но настройка осталась вместе с ним, и молча
	// принимать в ней мусор незачем.
	if !domain.Contains([]string{"info", "low", "medium", "high", "critical"}, cfg.SASTMinSeverity) {
		errs = append(errs, fmt.Errorf(
			"SAST_MIN_SEVERITY: недопустимое значение %q, ожидается info|low|medium|high|critical",
			cfg.SASTMinSeverity))
	}

	// Песочница включена явно, но адрес не задан — шаг не сможет ничего
	// проверить и будет звать DevSecOps на каждый пакет. Это противоречие в
	// настройках, а не умолчание, и сказать о нём надо на старте.
	if cfg.SandboxEnabled && strings.TrimSpace(cfg.SandboxURL) == "" {
		errs = append(errs, errors.New(
			"SANDBOX_URL: не задан при SANDBOX_ENABLED=true — шаг песочницы будет отдавать "+
				"каждый пакет на ручное решение DevSecOps. Задайте адрес или выключите шаг"))
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

// artifactRepos собирает карту «менеджер → репозиторий» по всем известным
// менеджерам. Имя переменной — ARTIFACT_REPO_{МЕНЕДЖЕР} в верхнем регистре,
// значение по умолчанию — «{менеджер}-internal».
func artifactRepos(getenv func(string) string) map[string]string {
	repos := make(map[string]string, len(domain.ManagerCodes))
	for _, manager := range domain.ManagerCodes {
		key := "ARTIFACT_REPO_" + strings.ToUpper(manager)
		repos[manager] = valueOr(getenv(key), manager+"-internal")
	}
	return repos
}

// ArtifactRepo — целевой репозиторий артефактори для менеджера. Пустая
// строка — менеджер неизвестен.
func (c *Config) ArtifactRepo(manager string) string {
	return c.ArtifactRepos[manager]
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
