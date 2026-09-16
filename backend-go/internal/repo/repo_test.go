package repo

import (
	"context"
	"os"
	"testing"

	"moderation/internal/db"
	"moderation/internal/domain"
)

// mustPool — реальный Postgres, не мок (принцип sentrix, см. docs/testing.md).
// Пропускается, если MODERATION_TEST_POSTGRES_DSN не задан — так интеграционный
// тест не роняет `go test ./...` там, где Postgres не поднят, но и не притворяется
// пройденным молча: сообщение явно называет причину пропуска.
func mustPool(t *testing.T) (*Repo, func()) {
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
	return New(pool), func() { pool.Close() }
}

// TestHappyPath — golden-сценарий №1 из docs/testing.md: заявка на pypi-пакет,
// все 9 шагов конвейера проходят pass, финальный статус approved. Пока без
// pipeline runner (фаза 2) шаги вставляются вручную — тест проверяет, что
// репозиторий корректно сохраняет и читает обратно всю цепочку
// package → package_version → moderation_request → request_item → 9×pipeline_step,
// включая обход через ListItemsByPackageVersion (опора для будущего
// siblings_awaiting).
func TestHappyPath_PyPI_AllStepsPass(t *testing.T) {
	r, cleanup := mustPool(t)
	defer cleanup()
	ctx := context.Background()

	pkg, err := r.GetOrCreatePackage(ctx, "pypi", "requests", "requests")
	if err != nil {
		t.Fatalf("GetOrCreatePackage: %v", err)
	}

	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "2.31.0", "2.31.0")
	if err != nil {
		t.Fatalf("CreatePackageVersion: %v", err)
	}
	// База между прогонами не пересоздаётся: без сброса заявки накапливаются, и
	// проверка «ровно два request_item на версию» начинает считать хвосты
	// прошлых запусков.
	resetItems(t, r, ver.ID)
	if ver.Status != "new" {
		t.Fatalf("новая версия должна быть в статусе new, получено %q", ver.Status)
	}

	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: mustUser(t, r, "repo-test-author"), Manager: "pypi", Status: "pending", Source: "api",
		Reason: strPtr("Сервис выставления счетов, спринт 41"),
	})
	if err != nil {
		t.Fatalf("CreateModerationRequest: %v", err)
	}

	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req.ID, PackageVersionID: ver.ID,
		RequestedName: "requests", RequestedVersion: "2.31.0",
		DependencyKind: "direct", Status: "queued",
	})
	if err != nil {
		t.Fatalf("CreateRequestItem: %v", err)
	}

	for order, code := range domain.StepCodes {
		if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
			RequestItemID: item.ID, StepCode: code, StepOrder: order, Result: "pass",
		}); err != nil {
			t.Fatalf("UpsertPipelineStep(%s): %v", code, err)
		}
	}

	steps, err := r.ListStepsByItem(ctx, item.ID)
	if err != nil {
		t.Fatalf("ListStepsByItem: %v", err)
	}
	if len(steps) != len(domain.StepCodes) {
		t.Fatalf("ожидалось %d шагов, получено %d", len(domain.StepCodes), len(steps))
	}
	for i, s := range steps {
		if s.StepCode != domain.StepCodes[i] {
			t.Fatalf("шаг %d: ожидался код %q, получен %q (порядок должен быть по step_order)", i, domain.StepCodes[i], s.StepCode)
		}
		if s.Result != "pass" {
			t.Fatalf("шаг %s: ожидался результат pass, получен %q", s.StepCode, s.Result)
		}
	}

	// Опора для siblings_awaiting (фаза 2): вторая заявка на ту же версию должна
	// быть видна через ListItemsByPackageVersion вместе с первой.
	req2, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: mustUser(t, r, "repo-test-author-2"), Manager: "pypi", Status: "pending", Source: "api",
	})
	if err != nil {
		t.Fatalf("CreateModerationRequest (второй автор): %v", err)
	}
	item2, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req2.ID, PackageVersionID: ver.ID,
		RequestedName: "requests", RequestedVersion: "2.31.0",
		DependencyKind: "direct", Status: "queued",
	})
	if err != nil {
		t.Fatalf("CreateRequestItem (второй автор): %v", err)
	}

	siblings, err := r.ListItemsByPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatalf("ListItemsByPackageVersion: %v", err)
	}
	if len(siblings) != 2 {
		t.Fatalf("ожидалось 2 request_item на одну версию пакета (оба автора), получено %d", len(siblings))
	}
	ids := map[int64]bool{item.ID: false, item2.ID: false}
	for _, s := range siblings {
		ids[s.ID] = true
	}
	for id, seen := range ids {
		if !seen {
			t.Fatalf("request_item %d не найден среди siblings по package_version_id", id)
		}
	}
}

// TestIdempotencyKey_NoDuplicate — контракт "повтор с тем же Idempotency-Key не
// создаёт дубль" (docs/user-stories.md, CI/автоматизация): второй insert с тем
// же ключом должен упасть на UNIQUE-ограничении, не тихо создать вторую заявку.
func TestIdempotencyKey_NoDuplicate(t *testing.T) {
	r, cleanup := mustPool(t)
	defer cleanup()
	ctx := context.Background()

	key := "ci-build-repo-test-idempotency"
	// Ключ идемпотентности переживает прогон: без сброса второй запуск падал бы
	// уже на ПЕРВОЙ вставке, и тест проверял бы не то, что заявлено.
	if _, err := r.pool.Exec(ctx, `DELETE FROM moderation_request WHERE idempotency_key = $1`, key); err != nil {
		t.Fatalf("сброс фикстуры idempotency key: %v", err)
	}

	first, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: mustUser(t, r, "repo-test-author"), Manager: "npm", Status: "pending", Source: "api",
		IdempotencyKey: &key,
	})
	if err != nil {
		t.Fatalf("первая заявка с idempotency key: %v", err)
	}

	existing, err := r.GetModerationRequestByIdempotencyKey(ctx, key)
	if err != nil {
		t.Fatalf("GetModerationRequestByIdempotencyKey: %v", err)
	}
	if existing == nil || existing.ID != first.ID {
		t.Fatalf("ожидалось найти существующую заявку %d по ключу, получено %+v", first.ID, existing)
	}

	if _, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: mustUser(t, r, "repo-test-author"), Manager: "npm", Status: "pending", Source: "api",
		IdempotencyKey: &key,
	}); err == nil {
		t.Fatal("повторная вставка с тем же Idempotency-Key должна была упасть на UNIQUE-ограничении")
	}
}

func strPtr(s string) *string { return &s }

// mustUser — пользователь для фикстуры. Раньше здесь стоял литерал AuthorID: 1
// с расчётом на пользователя, заведённого руками: на чистой базе тест падал на
// нарушении внешнего ключа. Тест обязан быть самодостаточным.
func mustUser(t *testing.T, r *Repo, username string) int64 {
	t.Helper()
	user, err := r.GetOrCreateUser(context.Background(), username, username)
	if err != nil {
		t.Fatalf("GetOrCreateUser(%q): %v", username, err)
	}
	return user.ID
}

// resetItems удаляет заявки на версию пакета (pipeline_step уходит каскадом).
func resetItems(t *testing.T, r *Repo, packageVersionID int64) {
	t.Helper()
	if _, err := r.pool.Exec(context.Background(),
		`DELETE FROM request_item WHERE package_version_id = $1`, packageVersionID); err != nil {
		t.Fatalf("сброс фикстуры request_item: %v", err)
	}
}

// TestItemsAwaitingScan — выборка наблюдателя: кого сканировать автоматически.
//
// Важны обе границы. Пакет, застрявший до скачивания (blacklist, карантин,
// нет в реестре), сканировать нечем — брать его в работу значит бесконечно
// пытаться и писать ошибки в лог. Пакет, у которого отчёт уже есть, брать
// повторно значит сканировать одно и то же по кругу на каждом тике.
func TestItemsAwaitingScan(t *testing.T) {
	r, cleanup := mustPool(t)
	defer cleanup()
	ctx := context.Background()

	pkg, err := r.GetOrCreatePackage(ctx, "pypi", "awaiting-scan-fixture", "awaiting-scan-fixture")
	if err != nil {
		t.Fatal(err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	resetItems(t, r, ver.ID)

	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: mustUser(t, r, "watcher-test-author"), Manager: "pypi",
		Status: "pending", Source: "ui",
	})
	if err != nil {
		t.Fatal(err)
	}
	newItem := func(status string) *domain.RequestItem {
		item, err := r.CreateRequestItem(ctx, domain.RequestItem{
			RequestID: req.ID, PackageVersionID: ver.ID,
			RequestedName: pkg.Name, RequestedVersion: "1.0.0",
			DependencyKind: "direct", Status: status,
		})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	downloaded := func(item *domain.RequestItem, result string) {
		if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
			RequestItemID: item.ID, StepCode: "download",
			StepOrder: domain.StepOrder["download"], Result: result,
		}); err != nil {
			t.Fatal(err)
		}
	}

	wantScan := newItem("awaiting_security") // скачан, отчётов нет — брать
	downloaded(wantScan, "pass")

	noDownload := newItem("blacklisted") // до скачивания не дошёл — не брать
	failedDownload := newItem("failed")  // скачивание не удалось — не брать
	downloaded(failedDownload, "fail")

	alreadyScanned := newItem("approved") // отчёт уже есть — не брать
	downloaded(alreadyScanned, "pass")
	if _, err := r.UpsertScanReport(ctx, domain.ScanReport{
		RequestItemID: alreadyScanned.ID, PackageVersionID: ver.ID,
		StepCode: "banner_scan", Scanner: "yara", State: "clean", Threshold: "info",
		JSONKey: "reports/x/banner_scan.json", HTMLKey: "reports/x/banner_scan.html",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := r.ItemsAwaitingScan(ctx, 50)
	if err != nil {
		t.Fatalf("ItemsAwaitingScan: %v", err)
	}
	inList := func(id int64) bool {
		for _, v := range got {
			if v == id {
				return true
			}
		}
		return false
	}
	if !inList(wantScan.ID) {
		t.Errorf("скачанный пакет без отчётов не попал в выборку: %v", got)
	}
	for _, c := range []struct {
		id  int64
		why string
	}{
		{noDownload.ID, "не дошёл до скачивания — сканировать нечего"},
		{failedDownload.ID, "скачивание не удалось — сканировать нечего"},
		{alreadyScanned.ID, "отчёт уже есть — сканировался бы по кругу"},
	} {
		if inList(c.id) {
			t.Errorf("пакет #%d попал в выборку, хотя %s", c.id, c.why)
		}
	}
}

func TestItemsAwaitingScanRespectsLimit(t *testing.T) {
	r, cleanup := mustPool(t)
	defer cleanup()
	got, err := r.ItemsAwaitingScan(context.Background(), 1)
	if err != nil {
		t.Fatalf("ItemsAwaitingScan: %v", err)
	}
	if len(got) > 1 {
		t.Errorf("вернулось %d пакетов при лимите 1", len(got))
	}
}
