package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// webEditable — несекретные настройки, которые допустимо хранить в БД.
// Изменения применяются при следующем запуске процесса; web-интерфейс прямо
// показывает это и не обещает горячую пересборку уже созданных клиентов.
var webEditable = map[string]bool{
	"APP_NAME":                           true,
	"LOCAL_AUTH_ENABLED":                  true,
	"QUARANTINE_DAYS":                     true,
	"VULN_MAX_SCORE":                      true,
	"ARTIFACT_STORE":                      true,
	"ARTIFACT_BASE_URL":                   true,
	"ARTIFACT_PUBLIC_BASE_URL":            true,
	"ARTIFACT_DOCKER_REGISTRY_URL":        true,
	"ARTIFACT_DOCKER_PUBLIC_URL":          true,
	"ARTIFACT_REPO_STAGING":               true,
	"ARTIFACT_REPO_REPORTS":               true,
	"ARTIFACT_REPO_OSV":                   true,
	"SANDBOX_ENABLED":                     true,
	"SANDBOX_URL":                         true,
	"SANDBOX_TIMEOUT_SECONDS":             true,
	"SANDBOX_INSECURE_TLS":                true,
	"DRAGON_ENABLED":                      true,
	"DRAGON_URL":                          true,
	"DRAGON_PIPELINE_ID":                  true,
	"DRAGON_STAGING_URL":                  true,
	"DRAGON_POLL_INTERVAL_SECONDS":         true,
	"DRAGON_TIMEOUT_SECONDS":               true,
	"DRAGON_MIN_SEVERITY":                  true,
	"OSV_DB_SOURCE":                       true,
	"OSV_PYPI_SNAPSHOT_PATH":              true,
	"OSV_NPM_SNAPSHOT_PATH":               true,
	"OSV_SYNC_INTERVAL_SECONDS":           true,
	"OSV_MAX_STALENESS_DAYS":              true,
	"OIDC_ISSUER":                         true,
	"OIDC_PUBLIC_ISSUER":                  true,
	"OIDC_CLIENT_ID":                      true,
	"GITLAB_URL":                          true,
	"MAX_PACKAGES_PER_REQUEST":            true,
	"RATE_LIMIT_REQUESTS_PER_MINUTE":       true,
	"PIPELINE_WATCHDOG_ENABLED":            true,
	"PIPELINE_WATCHDOG_INTERVAL_SECONDS":   true,
	"PIPELINE_STUCK_AFTER_SECONDS":         true,
	"REGISTRY_RETRY_ATTEMPTS":              true,
	"REGISTRY_BREAKER_THRESHOLD":           true,
}

// IsWebEditable сообщает API, какие строки каталога рисовать как поля ввода.
func IsWebEditable(key string) bool {
	if strings.HasPrefix(key, "ARTIFACT_REPO_") && key != "ARTIFACT_REPO_OSV" {
		return true
	}
	return webEditable[key]
}

// ValidateOverrides проверяет web-настройки до записи в БД.
func ValidateOverrides(values map[string]string) error {
	for key, value := range values {
		if !IsWebEditable(key) {
			return fmt.Errorf("настройка %s не редактируется через web", key)
		}
		if err := validateOverride(key, value); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

func validateOverride(key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "QUARANTINE_DAYS", "OSV_MAX_STALENESS_DAYS", "MAX_PACKAGES_PER_REQUEST",
		"RATE_LIMIT_REQUESTS_PER_MINUTE", "PIPELINE_WATCHDOG_INTERVAL_SECONDS",
		"PIPELINE_STUCK_AFTER_SECONDS", "REGISTRY_RETRY_ATTEMPTS", "REGISTRY_BREAKER_THRESHOLD",
		"SANDBOX_TIMEOUT_SECONDS", "OSV_SYNC_INTERVAL_SECONDS",
		"DRAGON_POLL_INTERVAL_SECONDS", "DRAGON_TIMEOUT_SECONDS":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return fmt.Errorf("ожидается неотрицательное целое число")
		}
	case "VULN_MAX_SCORE":
		n, err := strconv.ParseFloat(value, 64)
		if err != nil || n < 0 || n > 100 {
			return fmt.Errorf("ожидается число от 0 до 100")
		}
	case "LOCAL_AUTH_ENABLED", "SANDBOX_ENABLED", "SANDBOX_INSECURE_TLS", "DRAGON_ENABLED", "PIPELINE_WATCHDOG_ENABLED":
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("ожидается true или false")
		}
	case "ARTIFACT_BASE_URL", "ARTIFACT_PUBLIC_BASE_URL", "ARTIFACT_DOCKER_REGISTRY_URL",
		"ARTIFACT_DOCKER_PUBLIC_URL", "SANDBOX_URL", "DRAGON_URL", "DRAGON_STAGING_URL", "OIDC_ISSUER", "OIDC_PUBLIC_ISSUER",
		"GITLAB_URL":
		if value == "" && (key == "ARTIFACT_PUBLIC_BASE_URL" || key == "ARTIFACT_DOCKER_PUBLIC_URL") {
			return nil
		}
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("ожидается полный URL http(s)://host")
		}
	case "ARTIFACT_STORE":
		if value != "nexus" && value != "generic" {
			return fmt.Errorf("допустимо nexus или generic")
		}
	case "OSV_DB_SOURCE":
		if value != "artifactory" && value != "http" && value != "file" {
			return fmt.Errorf("допустимо artifactory, http или file")
		}
	case "DRAGON_MIN_SEVERITY":
		if value != "critical" && value != "high" && value != "medium" && value != "low" {
			return fmt.Errorf("допустимо critical, high, medium или low")
		}
	default:
		if value == "" {
			return fmt.Errorf("значение не должно быть пустым")
		}
	}
	return nil
}

// ApplyOverrides накладывает сохранённые web-настройки поверх .env до сборки
// клиентов и конвейера. Вызывать только на старте процесса.
func (c *Config) ApplyOverrides(values map[string]string) error {
	if err := ValidateOverrides(values); err != nil {
		return err
	}
	for key, raw := range values {
		v := strings.TrimSpace(raw)
		switch key {
		case "APP_NAME":
			c.AppName = v
		case "LOCAL_AUTH_ENABLED":
			c.LocalAuthEnabled, _ = strconv.ParseBool(v)
		case "QUARANTINE_DAYS":
			c.QuarantineDays, _ = strconv.Atoi(v)
		case "VULN_MAX_SCORE":
			c.VulnMaxScore, _ = strconv.ParseFloat(v, 64)
		case "ARTIFACT_STORE":
			c.ArtifactStore = v
		case "ARTIFACT_BASE_URL":
			c.ArtifactBaseURL = strings.TrimRight(v, "/")
		case "ARTIFACT_PUBLIC_BASE_URL":
			c.ArtifactPublicBaseURL = strings.TrimRight(v, "/")
		case "ARTIFACT_DOCKER_REGISTRY_URL":
			c.ArtifactDockerRegistryURL = strings.TrimRight(v, "/")
		case "ARTIFACT_DOCKER_PUBLIC_URL":
			c.ArtifactDockerPublicURL = strings.TrimRight(v, "/")
		case "ARTIFACT_REPO_STAGING":
			c.ArtifactRepoStaging = v
		case "ARTIFACT_REPO_REPORTS":
			c.ArtifactRepoReports = v
		case "ARTIFACT_REPO_OSV":
			c.ArtifactRepoOSV = v
		case "SANDBOX_ENABLED":
			c.SandboxEnabled, _ = strconv.ParseBool(v)
		case "SANDBOX_URL":
			c.SandboxURL = strings.TrimRight(v, "/")
		case "SANDBOX_TIMEOUT_SECONDS":
			n, _ := strconv.Atoi(v)
			c.SandboxTimeout = time.Duration(n) * time.Second
		case "SANDBOX_INSECURE_TLS":
			c.SandboxInsecureTLS, _ = strconv.ParseBool(v)
		case "DRAGON_ENABLED":
			c.DragonEnabled, _ = strconv.ParseBool(v)
		case "DRAGON_URL":
			c.DragonURL = strings.TrimRight(v, "/")
		case "DRAGON_PIPELINE_ID":
			c.DragonPipelineID = v
		case "DRAGON_STAGING_URL":
			c.DragonStagingURL = strings.TrimRight(v, "/")
		case "DRAGON_POLL_INTERVAL_SECONDS":
			n, _ := strconv.Atoi(v)
			c.DragonPollInterval = time.Duration(n) * time.Second
		case "DRAGON_TIMEOUT_SECONDS":
			n, _ := strconv.Atoi(v)
			c.DragonTimeout = time.Duration(n) * time.Second
		case "DRAGON_MIN_SEVERITY":
			c.DragonMinSeverity = v
		case "OSV_DB_SOURCE":
			c.OSVDBSource = v
		case "OSV_PYPI_SNAPSHOT_PATH":
			c.OSVPyPISnapshotPath = v
		case "OSV_NPM_SNAPSHOT_PATH":
			c.OSVNpmSnapshotPath = v
		case "OSV_SYNC_INTERVAL_SECONDS":
			n, _ := strconv.Atoi(v)
			c.OSVSyncInterval = time.Duration(n) * time.Second
		case "OSV_MAX_STALENESS_DAYS":
			c.OSVMaxStalenessDays, _ = strconv.Atoi(v)
		case "OIDC_ISSUER":
			c.OIDCIssuer = strings.TrimRight(v, "/")
		case "OIDC_PUBLIC_ISSUER":
			c.OIDCPublicIssuer = strings.TrimRight(v, "/")
		case "OIDC_CLIENT_ID":
			c.OIDCClientID = v
		case "GITLAB_URL":
			c.GitlabURL = strings.TrimRight(v, "/")
		case "MAX_PACKAGES_PER_REQUEST":
			c.MaxPackagesPerRequest, _ = strconv.Atoi(v)
		case "RATE_LIMIT_REQUESTS_PER_MINUTE":
			c.RateLimitPerMinute, _ = strconv.Atoi(v)
		case "PIPELINE_WATCHDOG_ENABLED":
			c.PipelineWatchdogEnabled, _ = strconv.ParseBool(v)
		case "PIPELINE_WATCHDOG_INTERVAL_SECONDS":
			n, _ := strconv.Atoi(v)
			c.PipelineWatchdogInterval = time.Duration(n) * time.Second
		case "PIPELINE_STUCK_AFTER_SECONDS":
			n, _ := strconv.Atoi(v)
			c.PipelineStuckAfter = time.Duration(n) * time.Second
		case "REGISTRY_RETRY_ATTEMPTS":
			c.RegistryRetryAttempts, _ = strconv.Atoi(v)
		case "REGISTRY_BREAKER_THRESHOLD":
			c.RegistryBreakerThreshold, _ = strconv.Atoi(v)
		default:
			if strings.HasPrefix(key, "ARTIFACT_REPO_") {
				manager := strings.ToLower(strings.TrimPrefix(key, "ARTIFACT_REPO_"))
				if c.ArtifactRepos == nil {
					c.ArtifactRepos = map[string]string{}
				}
				c.ArtifactRepos[manager] = v
			}
		}
	}
	return nil
}
