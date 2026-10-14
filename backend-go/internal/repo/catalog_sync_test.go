package repo

import (
	"context"
	"testing"
)

// PostgreSQL видит одновременно столбцы UPDATE-таблицы и CTE из FROM.
// Кандидат поэтому обязан называться candidate_id: неуточнённый id в
// RETURNING иначе падает с SQLSTATE 42702, и запуск навсегда остаётся queued.
func TestClaimCatalogSyncMovesQueuedRunToRunning(t *testing.T) {
	r, cleanup := mustPool(t)
	t.Cleanup(cleanup)
	ctx := context.Background()

	if _, err := r.pool.Exec(ctx, `DELETE FROM artifact_catalog_sync_run`); err != nil {
		t.Fatalf("очистка запусков синхронизации: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.pool.Exec(context.Background(), `DELETE FROM artifact_catalog_sync_run`)
	})

	queued, err := r.EnqueueCatalogSync(ctx, "manual", []string{"pypi", "npm", "go"}, nil)
	if err != nil {
		t.Fatalf("постановка в очередь: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("статус после постановки = %q, ожидался queued", queued.Status)
	}

	running, err := r.ClaimCatalogSync(ctx)
	if err != nil {
		t.Fatalf("захват запуска: %v", err)
	}
	if running == nil {
		t.Fatal("worker не получил ожидающий запуск")
	}
	if running.ID != queued.ID || running.Status != "running" || running.StartedAt == nil {
		t.Fatalf("захваченный запуск = %+v, ожидался running для #%d", running, queued.ID)
	}

	next, err := r.ClaimCatalogSync(ctx)
	if err != nil {
		t.Fatalf("повторный захват: %v", err)
	}
	if next != nil {
		t.Fatalf("один запуск выдан двум worker: %+v", next)
	}
}
