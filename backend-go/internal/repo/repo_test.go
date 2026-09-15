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
	if ver.Status != "new" {
		t.Fatalf("новая версия должна быть в статусе new, получено %q", ver.Status)
	}

	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: 1, Manager: "pypi", Status: "pending", Source: "api",
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
		AuthorID: 2, Manager: "pypi", Status: "pending", Source: "api",
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
	first, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: 1, Manager: "npm", Status: "pending", Source: "api",
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
		AuthorID: 1, Manager: "npm", Status: "pending", Source: "api",
		IdempotencyKey: &key,
	}); err == nil {
		t.Fatal("повторная вставка с тем же Idempotency-Key должна была упасть на UNIQUE-ограничении")
	}
}

func strPtr(s string) *string { return &s }
