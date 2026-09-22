package repo

import (
	"context"
	"fmt"
	"time"

	"moderation/internal/domain"
)

// Выборки для регламентных задач: истёкший карантин и зависшие объекты во
// временном хранилище. Порт запросов из backend/app/tasks/scheduled.py.

// ExpiredQuarantineItems — пакеты, у которых срок карантина вышел, а статус
// остался «в карантине».
//
// Условие по версии, а не по пакету заявки: карантин — свойство версии, и
// снимается он сразу со всех, кто эту версию заказал.
func (r *Repo) ExpiredQuarantineItems(ctx context.Context, now time.Time) ([]domain.RequestItem, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ri.id, ri.request_id, ri.package_version_id, ri.requested_name,
		       ri.requested_version, ri.dependency_kind, ri.parent_item_id, ri.depth,
		       ri.required_range, ri.status, ri.current_step, ri.next_action,
		       ri.blocked_reason, ri.waiting_since, ri.finished_at, ri.created_at, ri.updated_at
		FROM request_item ri
		JOIN package_version pv ON pv.id = ri.package_version_id
		WHERE ri.status = 'quarantined'
		  AND pv.quarantine_until IS NOT NULL
		  AND pv.quarantine_until <= $1
		ORDER BY ri.id
	`, now)
	if err != nil {
		return nil, fmt.Errorf("выборка пакетов с истёкшим карантином: %w", err)
	}
	defer rows.Close()

	var out []domain.RequestItem
	for rows.Next() {
		item, err := scanRequestItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *item)
	}
	return out, rows.Err()
}

// OrphanArtifacts — объекты, зависшие во временном хранилище дольше срока.
//
// «Зависший» — это загруженный, ещё не удалённый и достаточно старый. Такие
// остаются после прогонов, прерванных на середине: карантинная зона хранит
// байты пакетов, и без уборки она растёт, пока не кончится место.
func (r *Repo) OrphanArtifacts(ctx context.Context, cutoff time.Time) ([]domain.Artifact, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, package_version_id, filename, source_url, size_bytes, sha256,
		       declared_checksum, checksum_algo, s3_bucket, s3_key, s3_uploaded_at,
		       s3_deleted_at, nexus_url, published_at, status
		FROM artifact
		WHERE s3_key IS NOT NULL
		  AND s3_deleted_at IS NULL
		  AND s3_uploaded_at IS NOT NULL
		  AND s3_uploaded_at < $1
		ORDER BY id
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("выборка зависших объектов: %w", err)
	}
	defer rows.Close()

	var out []domain.Artifact
	for rows.Next() {
		artifact, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *artifact)
	}
	return out, rows.Err()
}

// DeactivateOtherIndexVersions — активной может быть только одна версия
// снапшота: по ней экран «Настройка» показывает, чем сейчас проверяют пакеты.
func (r *Repo) DeactivateOtherIndexVersions(ctx context.Context, keepID int64) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE vuln_index_version SET is_active = FALSE WHERE id <> $1 AND is_active`, keepID)
	if err != nil {
		return fmt.Errorf("снятие признака активной версии снапшота: %w", err)
	}
	return nil
}
