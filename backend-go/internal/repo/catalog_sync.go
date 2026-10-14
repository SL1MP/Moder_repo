package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CatalogSyncRun — служебный запуск обхода артефактори. Его status описывает
// только сам обход и никогда не копируется в статус версии пакета.
type CatalogSyncRun struct {
	ID            int64          `json:"id"`
	Status        string         `json:"status"`
	Trigger       string         `json:"trigger"`
	Managers      []string       `json:"managers"`
	RequestedByID *int64         `json:"requested_by_id,omitempty"`
	Discovered    int            `json:"discovered"`
	Imported      int            `json:"imported"`
	Updated       int            `json:"updated"`
	Skipped       int            `json:"skipped"`
	Errors        int            `json:"errors"`
	Details       map[string]any `json:"details"`
	Error         *string        `json:"error,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	StartedAt     *time.Time     `json:"started_at,omitempty"`
	FinishedAt    *time.Time     `json:"finished_at,omitempty"`
}

type CatalogArtifact struct {
	Manager     string
	Name        string
	DisplayName string
	Version     string
	RawVersion  string
	Filename    string
	URL         string
	SizeBytes   int64
	SHA256      string
	PublishedAt time.Time
}

type CatalogUpsertResult struct {
	VersionID  int64
	Imported   bool
	Changed    bool
	RequestIDs []int64
}

func scanCatalogSyncRun(row scanner) (*CatalogSyncRun, error) {
	var out CatalogSyncRun
	var managersRaw, detailsRaw []byte
	if err := row.Scan(&out.ID, &out.Status, &out.Trigger, &managersRaw,
		&out.RequestedByID, &out.Discovered, &out.Imported, &out.Updated,
		&out.Skipped, &out.Errors, &detailsRaw, &out.Error, &out.CreatedAt,
		&out.StartedAt, &out.FinishedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(managersRaw, &out.Managers); err != nil {
		return nil, fmt.Errorf("разбор менеджеров запуска синхронизации: %w", err)
	}
	if err := json.Unmarshal(detailsRaw, &out.Details); err != nil {
		return nil, fmt.Errorf("разбор результата синхронизации: %w", err)
	}
	return &out, nil
}

const catalogSyncColumns = `id, status, run_trigger, managers, requested_by_id,
       discovered, imported, updated, skipped, errors, details, error,
       created_at, started_at, finished_at`

// EnqueueCatalogSync создаёт один долговечный запуск. Если обход уже ожидает
// worker или выполняется, возвращает его: повторные клики не создают очередь
// одинаковых полных обходов.
func (r *Repo) EnqueueCatalogSync(
	ctx context.Context, trigger string, managers []string, requestedByID *int64,
) (*CatalogSyncRun, error) {
	managerJSON, err := json.Marshal(managers)
	if err != nil {
		return nil, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Несколько API/worker-процессов могут поставить обход одновременно.
	// Транзакционная advisory-блокировка закрывает окно между NOT EXISTS и
	// INSERT, не удерживаясь после завершения этого короткого метода.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('moderation:artifact-catalog-sync'))`); err != nil {
		return nil, fmt.Errorf("блокировка очереди синхронизации каталога: %w", err)
	}
	row := tx.QueryRow(ctx, `
		WITH inserted AS (
			INSERT INTO artifact_catalog_sync_run (status, run_trigger, managers, requested_by_id)
			SELECT 'queued', $1, $2::jsonb, $3
			WHERE NOT EXISTS (
				SELECT 1 FROM artifact_catalog_sync_run WHERE status IN ('queued', 'running')
			)
			RETURNING `+catalogSyncColumns+`
		), selected AS (
			SELECT * FROM inserted
			UNION ALL
			SELECT `+catalogSyncColumns+` FROM artifact_catalog_sync_run
			WHERE status IN ('queued', 'running') AND NOT EXISTS (SELECT 1 FROM inserted)
			ORDER BY id DESC LIMIT 1
		)
		SELECT `+catalogSyncColumns+` FROM selected LIMIT 1
	`, trigger, managerJSON, requestedByID)
	out, err := scanCatalogSyncRun(row)
	if err != nil {
		return nil, fmt.Errorf("постановка синхронизации каталога в очередь: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("фиксация синхронизации каталога в очереди: %w", err)
	}
	return out, nil
}

func (r *Repo) LatestCatalogSync(ctx context.Context) (*CatalogSyncRun, error) {
	out, err := scanCatalogSyncRun(r.pool.QueryRow(ctx, `
		SELECT `+catalogSyncColumns+` FROM artifact_catalog_sync_run ORDER BY id DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение последней синхронизации каталога: %w", err)
	}
	return out, nil
}

// RecoverCatalogSyncRuns освобождает запуск, оставшийся running после
// аварийной остановки worker. Иначе уникальный индекс навсегда запретил бы
// следующий обход.
func (r *Repo) RecoverCatalogSyncRuns(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE artifact_catalog_sync_run
		SET status = 'failed', error = 'worker остановился до завершения синхронизации',
		    finished_at = now()
		WHERE status = 'running' AND started_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("восстановление запусков синхронизации каталога: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ClaimCatalogSync атомарно передаёт один запуск одному worker.
func (r *Repo) ClaimCatalogSync(ctx context.Context) (*CatalogSyncRun, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	row := tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id FROM artifact_catalog_sync_run
			WHERE status = 'queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE artifact_catalog_sync_run run
		SET status = 'running', started_at = now(), error = NULL
		FROM candidate WHERE run.id = candidate.id
		RETURNING `+catalogSyncColumns)
	out, err := scanCatalogSyncRun(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("захват синхронизации каталога: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) FinishCatalogSync(ctx context.Context, id int64, result CatalogSyncRun, runErr error) error {
	status := "succeeded"
	var errorText *string
	if runErr != nil {
		status = "failed"
		text := runErr.Error()
		errorText = &text
	}
	details, err := json.Marshal(result.Details)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		UPDATE artifact_catalog_sync_run
		SET status = $2, discovered = $3, imported = $4, updated = $5,
		    skipped = $6, errors = $7, details = $8::jsonb, error = $9,
		    finished_at = now()
		WHERE id = $1`, id, status, result.Discovered, result.Imported,
		result.Updated, result.Skipped, result.Errors, details, errorText)
	if err != nil {
		return fmt.Errorf("завершение синхронизации каталога: %w", err)
	}
	return nil
}

// UpsertTrustedCatalogArtifacts переносит физический факт из доверенного
// moderated-репозитория в web-каталог. Повторной модерации нет: наличие в
// этом репозитории уже означает approved. При повторном обходе обновляются
// ссылка и фактические метаданные, но новая версия не создаётся.
func (r *Repo) UpsertTrustedCatalogArtifacts(
	ctx context.Context, artifacts []CatalogArtifact, now time.Time,
) (CatalogUpsertResult, error) {
	if len(artifacts) == 0 {
		return CatalogUpsertResult{}, fmt.Errorf("версия каталога не содержит артефактов")
	}
	a := artifacts[0]
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return CatalogUpsertResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var packageID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO package (manager, name, display_name)
		VALUES ($1, $2, $3)
		ON CONFLICT (manager, name) DO UPDATE
		SET display_name = CASE WHEN package.display_name = '' THEN EXCLUDED.display_name ELSE package.display_name END,
		    updated_at = now()
		RETURNING id`, a.Manager, a.Name, a.DisplayName).Scan(&packageID); err != nil {
		return CatalogUpsertResult{}, fmt.Errorf("пакет каталога: %w", err)
	}

	var versionID int64
	var imported bool
	publishedAt := a.PublishedAt
	for _, artifact := range artifacts[1:] {
		if !artifact.PublishedAt.IsZero() && (publishedAt.IsZero() || artifact.PublishedAt.Before(publishedAt)) {
			publishedAt = artifact.PublishedAt
		}
	}
	if publishedAt.IsZero() {
		publishedAt = now
	}
	reason := "Доступен во внутреннем артефактори; каталог синхронизирован автоматически"
	if err := tx.QueryRow(ctx, `
		INSERT INTO package_version
			(package_id, version, raw_version, status, published_at, approved_at,
			 status_reason, license_source)
		VALUES ($1, $2, $3, 'approved', $4, $5, $6, 'artifact_catalog')
		ON CONFLICT (package_id, version) DO UPDATE
		SET raw_version = EXCLUDED.raw_version, status = 'approved',
		    published_at = COALESCE(EXCLUDED.published_at, package_version.published_at),
		    approved_at = COALESCE(package_version.approved_at, EXCLUDED.approved_at),
		    revoked_at = NULL,
		    status_reason = CASE
		        WHEN package_version.status = 'approved'
		         AND NULLIF(package_version.status_reason, '') IS NOT NULL
		        THEN package_version.status_reason
		        ELSE EXCLUDED.status_reason
		    END,
		    updated_at = now()
		RETURNING id, (xmax = 0)`, packageID, a.Version, a.RawVersion,
		publishedAt, now, reason).Scan(&versionID, &imported); err != nil {
		return CatalogUpsertResult{}, fmt.Errorf("версия каталога: %w", err)
	}

	artifactInserted := false
	for _, artifact := range artifacts {
		if artifact.Manager != a.Manager || artifact.Name != a.Name || artifact.Version != a.Version {
			return CatalogUpsertResult{}, fmt.Errorf("в один пакет каталога попали разные координаты")
		}
		artifactPublishedAt := artifact.PublishedAt
		if artifactPublishedAt.IsZero() {
			artifactPublishedAt = publishedAt
		}
		var inserted bool
		if err := tx.QueryRow(ctx, `
			INSERT INTO artifact
				(package_version_id, filename, source_url, size_bytes, sha256,
				 checksum_algo, nexus_url, published_at, status)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), 'sha256', $3, $6, 'published')
			ON CONFLICT ON CONSTRAINT uq_artifact_package_version_id_filename DO UPDATE
			SET source_url = EXCLUDED.source_url, size_bytes = EXCLUDED.size_bytes,
			    sha256 = COALESCE(EXCLUDED.sha256, artifact.sha256),
			    checksum_algo = 'sha256', nexus_url = EXCLUDED.nexus_url,
			    published_at = EXCLUDED.published_at, status = 'published'
			RETURNING (xmax = 0)`, versionID, artifact.Filename, artifact.URL,
			artifact.SizeBytes, artifact.SHA256, artifactPublishedAt).Scan(&inserted); err != nil {
			return CatalogUpsertResult{}, fmt.Errorf("артефакт каталога %s: %w", artifact.Filename, err)
		}
		artifactInserted = artifactInserted || inserted
	}

	rows, err := tx.Query(ctx, `
		WITH changed AS (
			UPDATE request_item
			SET status = 'approved', current_step = 'publish', blocked_reason = $2,
			    next_action = NULL, waiting_since = NULL, finished_at = now(),
			    attempts = 0, resume_from_step = NULL, updated_at = now()
			WHERE package_version_id = $1 AND status NOT IN ('approved', 'cancelled')
			RETURNING id, request_id
		), steps AS (
			UPDATE pipeline_step ps
			SET result = 'pass', message = $2,
			    details = jsonb_build_object('source', 'artifact_catalog'),
			    started_at = COALESCE(ps.started_at, now()), finished_at = now()
			FROM changed c WHERE ps.request_item_id = c.id AND ps.step_code = 'publish'
			RETURNING ps.request_item_id
		)
		SELECT DISTINCT request_id FROM changed ORDER BY request_id`, versionID, reason)
	if err != nil {
		return CatalogUpsertResult{}, fmt.Errorf("обновление старых заявок: %w", err)
	}
	var requestIDs []int64
	for rows.Next() {
		var requestID int64
		if err := rows.Scan(&requestID); err != nil {
			rows.Close()
			return CatalogUpsertResult{}, err
		}
		requestIDs = append(requestIDs, requestID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return CatalogUpsertResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CatalogUpsertResult{}, err
	}
	for _, requestID := range requestIDs {
		if _, err := r.RecomputeRequestStatus(ctx, requestID); err != nil {
			return CatalogUpsertResult{}, err
		}
	}
	return CatalogUpsertResult{
		VersionID: versionID, Imported: imported,
		Changed: imported || artifactInserted, RequestIDs: requestIDs,
	}, nil
}
