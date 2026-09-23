package repo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"moderation/internal/domain"
)

// Чтение для экрана «Настройка» и журнала аудита.

// AuditFilter — по чему отбирать записи журнала.
//
// Все поля необязательны: журнал смотрят и целиком («что вообще происходило»),
// и прицельно («кто трогал вот эту заявку»). Второе — основной случай при
// разборе, и без фильтров он превращается в пролистывание сотен строк.
type AuditFilter struct {
	EntityType string
	EntityID   string
	Action     string
	Actor      string
	Limit      int
	Offset     int
}

// ListAuditLog — записи журнала, новые сверху.
func (r *Repo) ListAuditLog(ctx context.Context, f AuditFilter) ([]domain.AuditLog, error) {
	// Предел обязателен: журнал растёт на каждое действие в сервисе, и запрос
	// без предела однажды вернёт миллион строк в память API.
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	where := []string{"TRUE"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.EntityType != "" {
		add("entity_type = $%d", f.EntityType)
	}
	if f.EntityID != "" {
		add("entity_id = $%d", f.EntityID)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Actor != "" {
		add("actor_name = $%d", f.Actor)
	}
	args = append(args, limit, f.Offset)

	query := `
		SELECT id, actor_id, actor_name, actor_role, action, entity_type, entity_id,
		       old_value, new_value, source, comment, ip, request_id, created_at
		FROM audit_log
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY id DESC
		LIMIT $` + fmt.Sprint(len(args)-1) + ` OFFSET $` + fmt.Sprint(len(args))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("чтение журнала аудита: %w", err)
	}
	defer rows.Close()

	var out []domain.AuditLog
	for rows.Next() {
		var entry domain.AuditLog
		if err := rows.Scan(
			&entry.ID, &entry.ActorID, &entry.ActorName, &entry.ActorRole, &entry.Action,
			&entry.EntityType, &entry.EntityID, &entry.OldValue, &entry.NewValue,
			&entry.Source, &entry.Comment, &entry.IP, &entry.RequestID, &entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("разбор строки журнала аудита: %w", err)
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

// ListVulnIndexVersions — загруженные версии снапшота OSV, новые сверху.
//
// Ограничение жёсткое: версий накапливается по одной на каждую загрузку, и
// экрану «Настройка» нужны последние, а не вся история.
func (r *Repo) ListVulnIndexVersions(ctx context.Context, limit int) ([]domain.VulnIndexVersion, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, version, source, checksum, remote_path, local_path,
		       published_at, downloaded_at, record_count, is_active
		FROM vuln_index_version
		ORDER BY id DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("чтение версий снапшота OSV: %w", err)
	}
	defer rows.Close()

	var out []domain.VulnIndexVersion
	for rows.Next() {
		var v domain.VulnIndexVersion
		if err := rows.Scan(
			&v.ID, &v.Version, &v.Source, &v.Checksum, &v.RemotePath, &v.LocalPath,
			&v.PublishedAt, &v.DownloadedAt, &v.RecordCount, &v.IsActive,
		); err != nil {
			return nil, fmt.Errorf("разбор версии снапшота OSV: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// StuckItemIDs — пакеты, лежащие в очереди дольше minAge.
//
// Возвращает идентификаторы, а не количество: экран «Настройка» показывает
// именно их, чтобы «пакет вечно проверяется» не приходилось искать по логам
// контейнеров.
func (r *Repo) StuckItemIDs(ctx context.Context, minAge time.Duration, limit int) ([]int64, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id FROM request_item
		WHERE status = 'queued' AND updated_at < now() - $1::interval
		ORDER BY updated_at
		LIMIT $2`, minAge.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("поиск залежавшихся пакетов: %w", err)
	}
	defer rows.Close()

	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
