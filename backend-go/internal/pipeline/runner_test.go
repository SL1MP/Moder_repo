package pipeline_test

import (
	"context"
	"os"
	"testing"
	"time"

	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/pipeline"
	"moderation/internal/repo"
)

// mustRepo — реальный Postgres, принцип sentrix (docs/testing.md). Пропускает
// тест, если MODERATION_TEST_POSTGRES_DSN не задан.
func mustRepo(t *testing.T) (*repo.Repo, func()) {
	t.Helper()
	dsn := os.Getenv("MODERATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MODERATION_TEST_POSTGRES_DSN не задан — пропускаю интеграционный тест (см. docs/testing.md)")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("подключение к тестовому Postgres: %v", err)
	}
	return repo.New(pool), func() { pool.Close() }
}

// setup — создаёт package/package_version/moderation_request/request_item,
// готовые к прогону конвейера. author user id=1 должен существовать в БД
// (см. TestMain-подобный посев в repo_test.go — здесь используем то же
// соглашение о заранее заведённом пользователе).
func setup(t *testing.T, r *repo.Repo, name, version string) (*domain.Package, *domain.PackageVersion, *domain.RequestItem) {
	t.Helper()
	ctx := context.Background()

	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatalf("GetOrCreatePackage: %v", err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, version, version)
	if err != nil {
		t.Fatalf("CreatePackageVersion: %v", err)
	}
	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: 1, Manager: "pypi", Status: "pending", Source: "api",
	})
	if err != nil {
		t.Fatalf("CreateModerationRequest: %v", err)
	}
	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req.ID, PackageVersionID: ver.ID,
		RequestedName: name, RequestedVersion: version,
		DependencyKind: "direct", Status: "queued",
	})
	if err != nil {
		t.Fatalf("CreateRequestItem: %v", err)
	}
	return pkg, ver, item
}

func TestDbCheck_TerminalBranches(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	cases := []struct {
		initialStatus string
		wantItemStat  string
		wantResult    string
	}{
		{"approved", "approved", "pass"},
		{"blacklisted", "blacklisted", "fail"},
		{"revoked", "revoked", "fail"},
	}
	for _, c := range cases {
		t.Run(c.initialStatus, func(t *testing.T) {
			pkg, ver, item := setup(t, r, "requests", "2.31.0-"+c.initialStatus)
			if err := r.UpdatePackageVersionStatus(ctx, ver.ID, c.initialStatus, nil); err != nil {
				t.Fatalf("подготовка версии: %v", err)
			}
			ver.Status = c.initialStatus

			pc := &pipeline.Context{Package: pkg, Version: ver, Config: pipeline.Config{QuarantineDays: 14}}
			res, err := pipeline.Run(ctx, r, item, pc, "")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !res.Blocked || res.ItemStatus != c.wantItemStat {
				t.Fatalf("ожидался статус %q, получено %+v", c.wantItemStat, res)
			}

			steps, err := r.ListStepsByItem(ctx, item.ID)
			if err != nil {
				t.Fatalf("ListStepsByItem: %v", err)
			}
			if len(steps) != 1 || steps[0].StepCode != "db_check" || steps[0].Result != c.wantResult {
				t.Fatalf("ожидался единственный шаг db_check/%s, получено %+v", c.wantResult, steps)
			}
		})
	}
}

func TestBlacklist_Rejects(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	pkg, ver, item := setup(t, r, "left-pad", "1.3.0")
	pc := &pipeline.Context{
		Package: pkg, Version: ver, Config: pipeline.Config{QuarantineDays: 14},
		BL: &pipeline.InMemoryBlacklist{Rules: []pipeline.BlacklistRule{
			{Name: "left-pad", Versions: "*", Reason: "исторически проблемный пакет"},
		}},
	}

	res, err := pipeline.Run(ctx, r, item, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Blocked || res.ItemStatus != "blacklisted" {
		t.Fatalf("ожидался blacklisted, получено %+v", res)
	}

	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatalf("GetPackageVersion: %v", err)
	}
	if got.Status != "blacklisted" {
		t.Fatalf("версия должна получить статус blacklisted, получено %q", got.Status)
	}

	steps, err := r.ListStepsByItem(ctx, item.ID)
	if err != nil {
		t.Fatalf("ListStepsByItem: %v", err)
	}
	if len(steps) != 2 || steps[0].StepCode != "db_check" || steps[1].StepCode != "blacklist" || steps[1].Result != "fail" {
		t.Fatalf("ожидались шаги db_check(pass)+blacklist(fail), получено %+v", steps)
	}
}

func TestQuarantine_HoldsRecentlyPublished(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	pkg, ver, item := setup(t, r, "brand-new-pkg", "0.0.1")
	publishedYesterday := time.Now().Add(-24 * time.Hour)
	ver.PublishedAt = &publishedYesterday

	pc := &pipeline.Context{Package: pkg, Version: ver, Config: pipeline.Config{QuarantineDays: 14}}
	res, err := pipeline.Run(ctx, r, item, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Blocked || res.ItemStatus != "quarantined" {
		t.Fatalf("ожидался quarantined, получено %+v", res)
	}
	if ver.QuarantineUntil == nil {
		t.Fatal("QuarantineUntil должен быть установлен")
	}
	wantUntil := publishedYesterday.AddDate(0, 0, 14)
	if ver.QuarantineUntil.Sub(wantUntil).Abs() > time.Minute {
		t.Fatalf("QuarantineUntil = %v, ожидалось ~%v", ver.QuarantineUntil, wantUntil)
	}

	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatalf("GetPackageVersion: %v", err)
	}
	if got.Status != "quarantined" || got.QuarantineUntil == nil {
		t.Fatalf("версия в БД должна быть quarantined с заполненным QuarantineUntil, получено %+v", got)
	}
}

func TestQuarantine_PassesOldEnough(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	pkg, ver, item := setup(t, r, "old-stable-pkg", "3.0.0")
	publishedLongAgo := time.Now().AddDate(0, 0, -30)
	ver.PublishedAt = &publishedLongAgo
	spdx := "MIT"
	ver.LicenseSPDX = &spdx

	pc := &pipeline.Context{
		Package: pkg, Version: ver, Config: pipeline.Config{QuarantineDays: 14},
		Lic: &pipeline.InMemoryLicensePolicy{Allowed: map[string]bool{"mit": true}},
	}
	res, err := pipeline.Run(ctx, r, item, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Дальше шага 3 (license) конвейер не реализован — Blocked=false ожидаемо
	// (см. package doc в steps.go), это НЕ "одобрено", а "пройдено то, что
	// уже реализовано, без блокировок".
	if res.Blocked {
		t.Fatalf("не ожидалось блокировки при старой публикации + разрешённой лицензии, получено %+v", res)
	}

	steps, err := r.ListStepsByItem(ctx, item.ID)
	if err != nil {
		t.Fatalf("ListStepsByItem: %v", err)
	}
	if len(steps) != 4 {
		t.Fatalf("ожидались все 4 реализованных шага, получено %d: %+v", len(steps), steps)
	}
	for _, s := range steps {
		if s.Result != "pass" {
			t.Fatalf("шаг %s: ожидался pass, получено %s", s.StepCode, s.Result)
		}
	}
}

func TestLicense_WarnDoesNotStopConveyor(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	pkg, ver, item := setup(t, r, "unlicensed-pkg", "1.0.0")
	publishedLongAgo := time.Now().AddDate(0, 0, -30)
	ver.PublishedAt = &publishedLongAgo
	spdx := "SomeWeirdLicense-1.0"
	ver.LicenseSPDX = &spdx

	pc := &pipeline.Context{
		Package: pkg, Version: ver, Config: pipeline.Config{QuarantineDays: 14},
		Lic: &pipeline.InMemoryLicensePolicy{Allowed: map[string]bool{"mit": true}},
	}
	res, err := pipeline.Run(ctx, r, item, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Blocked || res.ItemStatus != "awaiting_legal" {
		t.Fatalf("ожидался awaiting_legal, получено %+v", res)
	}

	steps, err := r.ListStepsByItem(ctx, item.ID)
	if err != nil {
		t.Fatalf("ListStepsByItem: %v", err)
	}
	if len(steps) != 4 {
		t.Fatalf("license.Stop=false — конвейер должен был пройти все 4 реализованных шага, получено %d", len(steps))
	}
	last := steps[len(steps)-1]
	if last.StepCode != "license" || last.Result != "warn" {
		t.Fatalf("последний шаг должен быть license/warn, получено %+v", last)
	}

	got, err := r.GetRequestItem(ctx, item.ID)
	if err != nil {
		t.Fatalf("GetRequestItem: %v", err)
	}
	if got.Status != "awaiting_legal" || got.CurrentStep == nil || *got.CurrentStep != "license" {
		t.Fatalf("request_item в БД должен быть awaiting_legal/license, получено %+v", got)
	}
}
