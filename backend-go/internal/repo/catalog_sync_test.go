package repo

import (
	"context"
	"strings"
	"testing"
	"time"
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

// Максимальный Docker tag вместе с index digest занимает 200 символов.
// Такой образ встречается в корпоративном каталоге и раньше падал на
// package_version.version VARCHAR(128), оставляя частично завершённый импорт.
func TestTrustedCatalogAcceptsFullDockerTagAndDigest(t *testing.T) {
	r, cleanup := mustPool(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	name := "catalog-long-docker-version-test"
	version := strings.Repeat("a", 128) + "@sha256:" + strings.Repeat("b", 64)

	result, err := r.UpsertTrustedCatalogArtifacts(ctx, []CatalogArtifact{{
		Manager: "docker", Name: name, DisplayName: name,
		Version: version, RawVersion: version,
		Filename: "list.manifest.json",
		URL: "https://artifactory.example/docker/" + name + "/manifest.json",
		SHA256: strings.Repeat("b", 64), PublishedAt: time.Now().UTC(),
	}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("импорт Docker tag@digest длиной %d: %v", len(version), err)
	}
	if result.VersionID == 0 {
		t.Fatal("импорт не вернул package_version")
	}
	t.Cleanup(func() {
		_, _ = r.pool.Exec(context.Background(),
			`DELETE FROM package WHERE manager = 'docker' AND name = $1`, name)
	})

	row, err := r.GetVersionRow(ctx, result.VersionID)
	if err != nil || row == nil {
		t.Fatalf("чтение импортированной версии: row=%+v err=%v", row, err)
	}
	if row.Version.Version != version || row.Version.RawVersion != version {
		t.Fatalf("Docker-версия была обрезана: %+v", row.Version)
	}
}
