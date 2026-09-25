package config

import (
	"strings"
	"testing"
	"time"
)

// TestDefaultsMatchPython — сторож против расхождения умолчаний с
// python-версией (backend/app/core/config.py).
//
// Обе версии читают ОДИН .env и выносят вердикт по одному пакету. Если
// переменной в .env нет, каждая берёт своё умолчание — и при разных
// умолчаниях один и тот же пакет получает разный вердикт. Ровно это и
// случилось в бою: SAST_MIN_SEVERITY в .env отсутствовал, python применял
// порог high, Go — medium, и Go пометил блокирующими находки, которые python
// пропускал.
//
// Значения ниже сверены с backend/app/core/config.py. Меняются только вместе
// с ней и осознанно.
func TestDefaultsMatchPython(t *testing.T) {
	cfg, err := Load(func(key string) string {
		if key == "DATABASE_URL" {
			return "postgres://localhost/x"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name      string
		got, want any
	}{
		{"quarantine_days", cfg.QuarantineDays, 14},
		{"vuln_max_score", cfg.VulnMaxScore, 80.0},
		{"osv_max_staleness_days", cfg.OSVMaxStalenessDays, 3},
		// Шаги banner_scan и sast_scan сняты с конвейера (миграция 0013), и
		// значение по умолчанию у них сознательно РАСХОДИТСЯ с python-версией:
		// включённым должен оказаться только тот шаг, который вернули в строй
		// явно. Сам конвейер их всё равно не запускает — см. pipeline.Steps.
		{"banner_scan_enabled", cfg.BannerScanEnabled, false},
		{"banner_rules_file", cfg.BannerRulesFile, "/config/rules.yar"},
		{"blacklist_file", cfg.BlacklistFile, "/config/blacklist.yml"},
		{"allowed_licenses_file", cfg.AllowedLicensesFile, "/config/licenses.yml"},
		{"sast_enabled", cfg.SASTEnabled, false},
		{"sast_rules", cfg.SASTRules, "p/default"},
		{"sast_min_severity", cfg.SASTMinSeverity, "high"},
		{"scan_max_files", cfg.ScanMaxFiles, 20000},
		{"scan_max_unpacked_bytes", cfg.ScanMaxUnpackedBytes, int64(512 * 1024 * 1024)},
		{"max_artifact_size_bytes", cfg.MaxArtifactSizeBytes, int64(500 * 1024 * 1024)},
		{"max_docker_artifact_size_bytes", cfg.MaxDockerArtifactSizeBytes, int64(2 * 1024 * 1024 * 1024)},
		{"max_upload_size_bytes", cfg.MaxUploadSizeBytes, int64(5 * 1024 * 1024)},
		{"max_packages_per_request", cfg.MaxPackagesPerRequest, 200},
		{"artifact_base_url", cfg.ArtifactBaseURL, "http://nexus:8081"},
		{"artifact_docker_registry_url", cfg.ArtifactDockerRegistryURL, ""},
		{"artifact_docker_public_url", cfg.ArtifactDockerPublicURL, ""},
		{"artifact_repo_pypi", cfg.ArtifactRepo("pypi"), "pypi-internal"},
		{"artifact_repo_npm", cfg.ArtifactRepo("npm"), "npm-internal"},
		{"artifact_repo_go", cfg.ArtifactRepo("go"), "go-internal"},
		{"artifact_repo_nuget", cfg.ArtifactRepo("nuget"), "nuget-internal"},
		// Менеджеры, добавленные миграцией 0014: репозиторий по умолчанию
		// строится по тому же правилу, отдельной настройки не требуется.
		{"artifact_repo_docker", cfg.ArtifactRepo("docker"), "docker-internal"},
		{"artifact_repo_maven", cfg.ArtifactRepo("maven"), "maven-internal"},
		{"artifact_repo_files", cfg.ArtifactRepo("files"), "files-internal"},
		{"artifact_repo_staging", cfg.ArtifactRepoStaging, "moderation-staging"},
		{"artifact_repo_reports", cfg.ArtifactRepoReports, "moderation-reports"},
		// Без SANDBOX_URL шаг песочницы выключен: набор настроек по умолчанию
		// обязан быть рабочим. Включение адресом проверяется отдельно.
		{"sandbox_enabled", cfg.SandboxEnabled, false},
		{"sandbox_priority", cfg.SandboxPriority, 3},
		{"sandbox_short_result", cfg.SandboxShortResult, true},
		{"sandbox_timeout", cfg.SandboxTimeout, 900 * time.Second},
		{"oidc_client_id", cfg.OIDCClientID, "moderation-web"},
		{"role_mapping_admin", cfg.RoleMappingAdmin, "moderation-admin"},
		{"role_mapping_devsecops", cfg.RoleMappingDevSecOps, "moderation-devsecops"},
		{"role_mapping_legal", cfg.RoleMappingLegal, "moderation-legal"},
		{"role_mapping_developer", cfg.RoleMappingDeveloper, "moderation-developer"},
		{"local_auth_enabled", cfg.LocalAuthEnabled, false},
		{"local_auth_secret", cfg.LocalAuthSecret, "change-me-in-prod"},
		{"app_name", cfg.AppName, "Модерация пакетов"},
		{"comment_edit_window_minutes", cfg.CommentEditWindow, 15 * time.Minute},
		{"pipeline_stuck_after_seconds", cfg.PipelineStuckAfter, 120 * time.Second},
		{"artifact_auth_type", cfg.ArtifactAuthType, "basic"},
		{"artifact_dry_run", cfg.ArtifactDryRun, false},
		{"osv_local_db_path", cfg.OSVLocalDBPath, "/var/lib/osv-db/current"},
		{"osv_pypi_snapshot_path", cfg.OSVPyPISnapshotPath, "osv/latest/osv-pypi.zip"},
		{"osv_npm_snapshot_path", cfg.OSVNpmSnapshotPath, "osv/latest/osv-npm.zip"},
		{"registry_pypi_url", cfg.RegistryPyPIURL, "https://pypi.org"},
		{"registry_npm_url", cfg.RegistryNpmURL, "https://registry.npmjs.org"},
		{"registry_go_proxy", cfg.RegistryGoProxy, "https://proxy.golang.org"},
		{"registry_go_license_url", cfg.RegistryGoLicenseURL, "https://pkg.go.dev"},
		{"registry_nuget_url", cfg.RegistryNuGetURL, "https://api.nuget.org"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, у python-версии %v — один .env дал бы разный вердикт",
				c.name, c.got, c.want)
		}
	}
}

func TestDockerInstallLocationUsesPublicRegistryPrefix(t *testing.T) {
	cfg, err := Load(func(key string) string {
		switch key {
		case "DATABASE_URL":
			return "postgres://localhost/x"
		case "ARTIFACT_BASE_URL":
			return "http://nexus:8081"
		case "ARTIFACT_DOCKER_PUBLIC_URL":
			return "https://packages.example/docker-internal/"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	base, repo := cfg.ArtifactInstallLocation("docker")
	if base != "https://packages.example/docker-internal" || repo != "" {
		t.Fatalf("Docker install location = (%q, %q)", base, repo)
	}
	base, repo = cfg.ArtifactInstallLocation("pypi")
	if base != "http://nexus:8081" || repo != "pypi-internal" {
		t.Fatalf("PyPI install location = (%q, %q)", base, repo)
	}
}

// TestBannerTimeoutIsSeparateVariable — BANNER_SCAN_TIMEOUT_SECONDS у
// python-версии значит таймаут на ОДИН файл (умолчание 10 с), а Go запускает
// yara на всё дерево сразу. Переиспользовать ту же переменную нельзя: 10 с на
// всё дерево означали бы, что проверка почти всегда обрывается и отдаёт «не
// выполнена» — то есть молча зовёт DevSecOps на каждом пакете.
func TestBannerTimeoutIsSeparateVariable(t *testing.T) {
	cfg, err := Load(func(key string) string {
		switch key {
		case "DATABASE_URL":
			return "postgres://localhost/x"
		case "BANNER_SCAN_TIMEOUT_SECONDS":
			return "10" // значение python-версии; Go его брать не должен
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BannerScanTimeout.Seconds() == 10 {
		t.Error("Go взял таймаут на один файл как таймаут на всё дерево")
	}
	if cfg.BannerScanTimeout.Seconds() != 300 {
		t.Errorf("BannerScanTimeout = %v, ожидалось 300с по умолчанию", cfg.BannerScanTimeout)
	}
}

func TestInvalidSASTSeverityRejected(t *testing.T) {
	_, err := Load(func(key string) string {
		switch key {
		case "DATABASE_URL":
			return "postgres://localhost/x"
		case "SAST_MIN_SEVERITY":
			return "hight" // опечатка
		}
		return ""
	})
	if err == nil {
		t.Fatal("опечатка в SAST_MIN_SEVERITY принята — порог тихо стал бы другим")
	}
}

// TestAllValidationErrorsAtOnce — паттерн sentrix: конфигурация возвращает все
// ошибки разом, а не падает на первой.
func TestAllValidationErrorsAtOnce(t *testing.T) {
	_, err := Load(func(key string) string {
		switch key {
		case "APP_ENV":
			return "нечто"
		case "SAST_MIN_SEVERITY":
			return "нечто"
		}
		return "" // DATABASE_URL пуст — третья ошибка
	})
	if err == nil {
		t.Fatal("невалидная конфигурация принята")
	}
	for _, want := range []string{"APP_ENV", "DATABASE_URL", "SAST_MIN_SEVERITY"} {
		if !contains(err.Error(), want) {
			t.Errorf("в сообщении нет ошибки про %s: %v", want, err)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// Стиль адресации S3 должен настраиваться: клиент умеет оба, а внешние
// хранилища (в отличие от MinIO и SeaweedFS рядом в compose) часто требуют
// virtual-host. Пока настройки не было, подключить такое хранилище было
// нельзя — и это выяснялось уже на живом стенде.
// Промежуточная зона обязана отличаться от целевых репозиториев: иначе
// непроверенный пакет лежал бы там, откуда его ставят разработчики. Проверка
// на старте, а не в рантайме — такую опечатку нельзя обнаруживать пакетом,
// который уже уехал.
func TestStagingRepoMustDifferFromTargetRepos(t *testing.T) {
	base := map[string]string{
		"DATABASE_URL":          "postgres://localhost/moderation",
		"ARTIFACT_REPO_STAGING": "pypi-internal",
	}
	_, err := Load(func(k string) string { return base[k] })
	if err == nil {
		t.Fatal("совпадение промежуточной зоны с репозиторием pypi должно быть ошибкой конфигурации")
	}
	if !strings.Contains(err.Error(), "ARTIFACT_REPO_STAGING") {
		t.Errorf("ошибка не называет виновную настройку: %v", err)
	}
}

// Песочница включена по умолчанию, и включённая без адреса она отдавала бы
// каждый пакет на ручное решение. Это почти наверняка не то, чего хотели.
func TestSandboxEnabledWithoutURLIsConfigError(t *testing.T) {
	base := map[string]string{
		"DATABASE_URL":    "postgres://localhost/moderation",
		"SANDBOX_ENABLED": "true",
	}
	_, err := Load(func(k string) string { return base[k] })
	if err == nil {
		t.Fatal("SANDBOX_ENABLED=true без SANDBOX_URL должен быть ошибкой конфигурации")
	}
	if !strings.Contains(err.Error(), "SANDBOX_URL") {
		t.Errorf("ошибка не называет виновную настройку: %v", err)
	}
}

// Заданный адрес песочницы сам включает шаг: заводить две настройки там, где
// достаточно одной, значит получить инсталляцию с адресом и выключенным шагом.
func TestSandboxEnabledByURL(t *testing.T) {
	base := map[string]string{
		"DATABASE_URL": "postgres://localhost/moderation",
		"SANDBOX_URL":  "https://sandbox.example.com",
	}
	cfg, err := Load(func(k string) string { return base[k] })
	if err != nil {
		t.Fatalf("конфигурация: %v", err)
	}
	if !cfg.SandboxEnabled {
		t.Error("заданный SANDBOX_URL должен включать шаг песочницы")
	}

	// Явное выключение важнее адреса: выключить шаг, не стирая адрес, — это
	// обычный способ временно снять проверку.
	base["SANDBOX_ENABLED"] = "false"
	cfg, err = Load(func(k string) string { return base[k] })
	if err != nil {
		t.Fatalf("конфигурация: %v", err)
	}
	if cfg.SandboxEnabled {
		t.Error("SANDBOX_ENABLED=false должен выключать шаг даже при заданном адресе")
	}
}

// SEC_TOKEN — имя переменной из CI-шаблона. Тот же секрет не должен
// требовать второго имени только потому, что его читает другой сервис.
func TestSandboxTokenFallsBackToSecToken(t *testing.T) {
	base := map[string]string{
		"DATABASE_URL": "postgres://localhost/moderation",
		"SANDBOX_URL":  "https://sandbox.example.com",
		"SEC_TOKEN":    "from-ci",
	}
	cfg, err := Load(func(k string) string { return base[k] })
	if err != nil {
		t.Fatalf("конфигурация: %v", err)
	}
	if cfg.SandboxToken != "from-ci" {
		t.Errorf("SEC_TOKEN не подхвачен: %q", cfg.SandboxToken)
	}

	// Своё имя важнее: если заданы оба, выигрывает SANDBOX_TOKEN.
	base["SANDBOX_TOKEN"] = "own"
	cfg, err = Load(func(k string) string { return base[k] })
	if err != nil {
		t.Fatalf("конфигурация: %v", err)
	}
	if cfg.SandboxToken != "own" {
		t.Errorf("SANDBOX_TOKEN должен быть важнее SEC_TOKEN, получено %q", cfg.SandboxToken)
	}
}

// Прежние имена настроек уборки продолжают работать.
//
// S3 из сервиса убран, но `S3_CLEANUP_INTERVAL_SECONDS` и
// `S3_ORPHAN_TTL_HOURS` могли быть заданы в .env уже развёрнутых стендов.
// Молча вернуть их к значению по умолчанию — значит однажды обнаружить
// промежуточную зону, которая убирается по расписанию, о котором никто не
// договаривался; заметить это можно только по её размеру.
func TestStagingCleanupAcceptsFormerEnvNames(t *testing.T) {
	cases := []struct {
		name         string
		env          map[string]string
		wantInterval time.Duration
		wantTTL      time.Duration
	}{
		{
			name:         "прежние имена",
			env:          map[string]string{"S3_CLEANUP_INTERVAL_SECONDS": "60", "S3_ORPHAN_TTL_HOURS": "5"},
			wantInterval: time.Minute,
			wantTTL:      5 * time.Hour,
		},
		{
			name:         "новые имена",
			env:          map[string]string{"STAGING_CLEANUP_INTERVAL_SECONDS": "120", "STAGING_ORPHAN_TTL_HOURS": "7"},
			wantInterval: 2 * time.Minute,
			wantTTL:      7 * time.Hour,
		},
		{
			// Новое имя выигрывает: иначе забытая прежняя переменная тихо
			// побеждала бы ту, которую только что вписали, — и настройка
			// выглядела бы неработающей.
			name: "заданы оба — выигрывает новое",
			env: map[string]string{
				"S3_CLEANUP_INTERVAL_SECONDS": "60", "STAGING_CLEANUP_INTERVAL_SECONDS": "120",
				"S3_ORPHAN_TTL_HOURS": "5", "STAGING_ORPHAN_TTL_HOURS": "7",
			},
			wantInterval: 2 * time.Minute,
			wantTTL:      7 * time.Hour,
		},
		{
			name:         "не задано ничего",
			env:          map[string]string{},
			wantInterval: 2 * time.Hour,
			wantTTL:      24 * time.Hour,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"DATABASE_URL": "postgres://localhost/moderation"}
			for k, v := range tc.env {
				env[k] = v
			}
			cfg, err := Load(func(k string) string { return env[k] })
			if err != nil {
				t.Fatalf("конфигурация не загрузилась: %v", err)
			}
			if cfg.StagingCleanupInterval != tc.wantInterval {
				t.Errorf("интервал уборки %v, ожидался %v", cfg.StagingCleanupInterval, tc.wantInterval)
			}
			if cfg.StagingOrphanTTL != tc.wantTTL {
				t.Errorf("срок жизни файла %v, ожидался %v", cfg.StagingOrphanTTL, tc.wantTTL)
			}
		})
	}
}
