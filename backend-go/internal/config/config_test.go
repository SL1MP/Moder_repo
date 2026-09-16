package config

import (
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
		{"banner_scan_enabled", cfg.BannerScanEnabled, true},
		{"banner_rules_file", cfg.BannerRulesFile, "/config/rules.yar"},
		{"blacklist_file", cfg.BlacklistFile, "/config/blacklist.yml"},
		{"allowed_licenses_file", cfg.AllowedLicensesFile, "/config/licenses.yml"},
		{"sast_enabled", cfg.SASTEnabled, true},
		{"sast_rules", cfg.SASTRules, "p/default"},
		{"sast_min_severity", cfg.SASTMinSeverity, "high"},
		{"scan_max_files", cfg.ScanMaxFiles, 20000},
		{"scan_max_unpacked_bytes", cfg.ScanMaxUnpackedBytes, int64(512 * 1024 * 1024)},
		{"max_artifact_size_bytes", cfg.MaxArtifactSizeBytes, int64(500 * 1024 * 1024)},
		{"max_upload_size_bytes", cfg.MaxUploadSizeBytes, int64(5 * 1024 * 1024)},
		{"max_packages_per_request", cfg.MaxPackagesPerRequest, 200},
		{"artifact_base_url", cfg.ArtifactBaseURL, "http://nexus:8081"},
		{"artifact_repo_pypi", cfg.ArtifactRepoPyPI, "pypi-internal"},
		{"artifact_repo_npm", cfg.ArtifactRepoNpm, "npm-internal"},
		{"artifact_repo_go", cfg.ArtifactRepoGo, "go-internal"},
		{"artifact_repo_nuget", cfg.ArtifactRepoNuGet, "nuget-internal"},
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
		{"osv_local_db_path", cfg.OSVLocalDBPath, "/var/lib/osv-db"},
		{"registry_pypi_url", cfg.RegistryPyPIURL, "https://pypi.org"},
		{"registry_npm_url", cfg.RegistryNpmURL, "https://registry.npmjs.org"},
		{"registry_go_proxy", cfg.RegistryGoProxy, "https://proxy.golang.org"},
		{"registry_nuget_url", cfg.RegistryNuGetURL, "https://api.nuget.org"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, у python-версии %v — один .env дал бы разный вердикт",
				c.name, c.got, c.want)
		}
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
