package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

// Очереди ролей, обсуждения и уведомления.

// --------------------------------------------------------------------------- очереди

// QueueRow — пакет, ждущий решения роли.
type QueueRow struct {
	Item           domain.RequestItem
	Manager        string
	Author         *string
	LicenseSPDX    *string
	MaxVulnScore   *float64
	LicenseClaimID *int64
}

// finishedStatuses — пакет с окончательным вердиктом ни в одной очереди не нужен.
var finishedStatuses = []string{"approved", "rejected", "blacklisted", "revoked", "failed"}

// QueueItems — очередь роли. Порт decisions._queue.
//
// Отбор идёт не только по статусу пакета, и это принципиально: согласования
// параллельны, а статус у пакета один. Если лицензия ждёт юриста, а уязвимости
// — DevSecOps, статусом станет более блокирующий awaiting_security, и в
// очереди юристов пакет по статусу не нашёлся бы вовсе. Поэтому вторым
// условием берутся сами шаги: результат warn или fail означает непогашенное
// решение своей роли.
//
// Номер заявления лицензии подтягивается тем же запросом (LATERAL), а не
// отдельным на каждую строку: очередь юристов открывают десятки раз в день.
func (r *Repo) QueueItems(ctx context.Context, statuses, stepCodes []string) ([]QueueRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ri.id, ri.request_id, ri.package_version_id, ri.requested_name, ri.requested_version,
		       ri.dependency_kind, ri.parent_item_id, ri.depth, ri.required_range,
		       ri.status, ri.current_step, ri.next_action, ri.blocked_reason,
		       ri.waiting_since, ri.finished_at, ri.created_at, ri.updated_at,
		       p.manager, u.username, pv.license_spdx, pv.max_vuln_score, claim.id
		FROM request_item ri
		JOIN package_version pv ON pv.id = ri.package_version_id
		JOIN package p ON p.id = pv.package_id
		JOIN moderation_request mr ON mr.id = ri.request_id
		LEFT JOIN "user" u ON u.id = mr.author_id
		LEFT JOIN LATERAL (
			SELECT lc.id FROM license_claim lc
			WHERE lc.package_version_id = pv.id AND lc.status = 'pending'
			ORDER BY lc.id DESC LIMIT 1
		) claim ON TRUE
		WHERE ri.status = ANY($1)
		   OR (
		        ri.status <> ALL($2)
		        AND EXISTS (
		          SELECT 1 FROM pipeline_step ps
		          WHERE ps.request_item_id = ri.id
		            AND ps.step_code = ANY($3)
		            AND ps.result IN ('warn', 'fail')
		        )
		      )
		ORDER BY ri.waiting_since ASC NULLS LAST, ri.id ASC
	`, statuses, finishedStatuses, stepCodes)
	if err != nil {
		return nil, fmt.Errorf("чтение очереди: %w", err)
	}
	defer rows.Close()

	var out []QueueRow
	for rows.Next() {
		var row QueueRow
		i := &row.Item
		if err := rows.Scan(&i.ID, &i.RequestID, &i.PackageVersionID, &i.RequestedName,
			&i.RequestedVersion, &i.DependencyKind, &i.ParentItemID, &i.Depth, &i.RequiredRange,
			&i.Status, &i.CurrentStep, &i.NextAction,
			&i.BlockedReason, &i.WaitingSince, &i.FinishedAt, &i.CreatedAt, &i.UpdatedAt,
			&row.Manager, &row.Author, &row.LicenseSPDX, &row.MaxVulnScore,
			&row.LicenseClaimID); err != nil {
			return nil, fmt.Errorf("чтение строки очереди: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// CountItemsByStatus — сколько пакетов в перечисленных статусах. Для счётчиков
// на значках очередей.
func (r *Repo) CountItemsByStatus(ctx context.Context, statuses []string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM request_item WHERE status = ANY($1)`, statuses).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("подсчёт пакетов по статусу: %w", err)
	}
	return n, nil
}

// --------------------------------------------------------------------------- обсуждения

const commentColumns = `c.id, c.request_id, c.request_item_id, c.author_id, c.author_role,
	c.body, c.mentions, c.is_edited, c.edited_at, c.deleted_at, c.created_at, c.updated_at`

// CommentRow — сообщение вместе с логином автора.
type CommentRow struct {
	Comment domain.Comment
	Author  *string
}

func scanComment(row scanner) (*CommentRow, error) {
	var out CommentRow
	c := &out.Comment
	var mentions []byte
	if err := row.Scan(&c.ID, &c.RequestID, &c.RequestItemID, &c.AuthorID, &c.AuthorRole,
		&c.Body, &mentions, &c.IsEdited, &c.EditedAt, &c.DeletedAt, &c.CreatedAt, &c.UpdatedAt,
		&out.Author); err != nil {
		return nil, err
	}
	if err := unmarshalInto(mentions, &out.Comment.Mentions); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListComments — ветка обсуждения заявки целиком или одного её пакета.
func (r *Repo) ListComments(ctx context.Context, requestID int64, itemID *int64) ([]CommentRow, error) {
	query := `SELECT ` + commentColumns + `, u.username
		FROM comment c LEFT JOIN "user" u ON u.id = c.author_id
		WHERE c.request_id = $1`
	args := []any{requestID}
	if itemID != nil {
		query += ` AND c.request_item_id = $2`
		args = append(args, *itemID)
	}
	query += ` ORDER BY c.id ASC`

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("чтение обсуждения: %w", err)
	}
	defer rows.Close()

	var out []CommentRow
	for rows.Next() {
		item, err := scanComment(rows)
		if err != nil {
			return nil, fmt.Errorf("чтение сообщения: %w", err)
		}
		out = append(out, *item)
	}
	return out, rows.Err()
}

// GetComment — сообщение по идентификатору. nil, если нет.
func (r *Repo) GetComment(ctx context.Context, id int64) (*CommentRow, error) {
	row, err := scanComment(r.pool.QueryRow(ctx, `SELECT `+commentColumns+`, u.username
		FROM comment c LEFT JOIN "user" u ON u.id = c.author_id WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение сообщения #%d: %w", id, err)
	}
	return row, nil
}

// CreateComment добавляет сообщение.
func (r *Repo) CreateComment(ctx context.Context, c domain.Comment) (*CommentRow, error) {
	mentions, err := jsonOrNull(nilIfNoMentions(c.Mentions))
	if err != nil {
		return nil, err
	}
	row, err := scanComment(r.pool.QueryRow(ctx, `
		WITH inserted AS (
			INSERT INTO comment (request_id, request_item_id, author_id, author_role, body,
			                     mentions, is_edited)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb, FALSE)
			RETURNING *
		)
		SELECT `+commentColumns+`, u.username
		FROM inserted c LEFT JOIN "user" u ON u.id = c.author_id`,
		c.RequestID, c.RequestItemID, c.AuthorID, c.AuthorRole, c.Body, mentions))
	if err != nil {
		return nil, fmt.Errorf("добавление сообщения: %w", err)
	}
	return row, nil
}

// UpdateCommentBody меняет текст сообщения. markEdited=false — правка внутри
// окна, пометки «изменено» не будет.
func (r *Repo) UpdateCommentBody(ctx context.Context, id int64, body string, markEdited bool, now time.Time) (*CommentRow, error) {
	var editedAt *time.Time
	if markEdited {
		editedAt = &now
	}
	row, err := scanComment(r.pool.QueryRow(ctx, `
		WITH updated AS (
			UPDATE comment
			SET body = $2,
			    is_edited = is_edited OR $3,
			    edited_at = COALESCE($4, edited_at),
			    updated_at = $5
			WHERE id = $1
			RETURNING *
		)
		SELECT `+commentColumns+`, u.username
		FROM updated c LEFT JOIN "user" u ON u.id = c.author_id`,
		id, body, markEdited, editedAt, now))
	if err != nil {
		return nil, fmt.Errorf("правка сообщения #%d: %w", id, err)
	}
	return row, nil
}

// SoftDeleteComment помечает сообщение удалённым. Строка остаётся: на неё
// ссылается аудит, и физическое удаление сделало бы историю нечитаемой.
func (r *Repo) SoftDeleteComment(ctx context.Context, id int64, now time.Time) (*CommentRow, error) {
	row, err := scanComment(r.pool.QueryRow(ctx, `
		WITH deleted AS (
			UPDATE comment SET deleted_at = $2, updated_at = $2 WHERE id = $1 RETURNING *
		)
		SELECT `+commentColumns+`, u.username
		FROM deleted c LEFT JOIN "user" u ON u.id = c.author_id`, id, now))
	if err != nil {
		return nil, fmt.Errorf("удаление сообщения #%d: %w", id, err)
	}
	return row, nil
}

// CommentAuthorIDs — кто уже писал в ветку заявки. Нужен, чтобы уведомить
// участников обсуждения, а не только автора заявки.
func (r *Repo) CommentAuthorIDs(ctx context.Context, requestID int64) ([]int64, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT author_id FROM comment WHERE request_id = $1`, requestID)
	if err != nil {
		return nil, fmt.Errorf("чтение участников обсуждения: %w", err)
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

// UserIDsByUsernames — идентификаторы по логинам. Для разбора упоминаний:
// несуществующий логин просто не даёт получателя, а не ломает отправку.
func (r *Repo) UserIDsByUsernames(ctx context.Context, usernames []string) ([]int64, error) {
	if len(usernames) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id FROM "user" WHERE username = ANY($1)`, usernames)
	if err != nil {
		return nil, fmt.Errorf("поиск упомянутых пользователей: %w", err)
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

// --------------------------------------------------------------------------- уведомления

// InsertNotifications раскладывает уведомление по получателям. Повторы в
// списке схлопываются: упомянуть человека и быть автором заявки — не повод
// прислать ему два одинаковых уведомления.
func (r *Repo) InsertNotifications(ctx context.Context, userIDs []int64, n domain.Notification) (int, error) {
	seen := map[int64]bool{}
	created := 0
	payload, err := jsonOrNull(n.Payload)
	if err != nil {
		return 0, err
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	for _, uid := range userIDs {
		if uid == 0 || seen[uid] {
			continue
		}
		seen[uid] = true
		_, err := r.pool.Exec(ctx, `
			INSERT INTO notification (user_id, event, title, body, request_id, request_item_id,
			                          payload, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`,
			uid, n.Event, n.Title, n.Body, n.RequestID, n.RequestItemID, payload, n.CreatedAt)
		if err != nil {
			return created, fmt.Errorf("создание уведомления: %w", err)
		}
		created++
	}
	return created, nil
}

// ListNotifications — уведомления пользователя, свежие первыми.
func (r *Repo) ListNotifications(ctx context.Context, userID int64, onlyUnread bool, limit int) ([]domain.Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `SELECT id, user_id, event, title, body, request_id, request_item_id, payload,
	                 created_at, read_at
	          FROM notification WHERE user_id = $1`
	if onlyUnread {
		query += ` AND read_at IS NULL`
	}
	query += ` ORDER BY id DESC LIMIT $2`

	rows, err := r.pool.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("чтение уведомлений: %w", err)
	}
	defer rows.Close()

	var out []domain.Notification
	for rows.Next() {
		var n domain.Notification
		var payload []byte
		if err := rows.Scan(&n.ID, &n.UserID, &n.Event, &n.Title, &n.Body, &n.RequestID,
			&n.RequestItemID, &payload, &n.CreatedAt, &n.ReadAt); err != nil {
			return nil, fmt.Errorf("чтение строки уведомления: %w", err)
		}
		if err := unmarshalInto(payload, &n.Payload); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CountUnreadNotifications — сколько непрочитанных.
func (r *Repo) CountUnreadNotifications(ctx context.Context, userID int64) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM notification WHERE user_id = $1 AND read_at IS NULL`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("подсчёт непрочитанных уведомлений: %w", err)
	}
	return n, nil
}

// MarkNotificationsRead отмечает прочитанными все или перечисленные.
// Фильтр по user_id обязателен: без него чужой идентификатор в списке пометил
// бы прочитанным чужое уведомление.
func (r *Repo) MarkNotificationsRead(ctx context.Context, userID int64, ids []int64, all bool, now time.Time) (int, error) {
	query := `UPDATE notification SET read_at = $2 WHERE user_id = $1 AND read_at IS NULL`
	args := []any{userID, now}
	if !all {
		query += ` AND id = ANY($3)`
		args = append(args, ids)
	}
	tag, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("отметка уведомлений прочитанными: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func nilIfNoMentions(mentions []string) any {
	if len(mentions) == 0 {
		return nil
	}
	return mentions
}

// UserIDsByRoles — активные пользователи, у которых есть хотя бы одна из
// ролей. Роли лежат JSON-массивом, поэтому сверка идёт оператором
// пересечения jsonb, а не выборкой всех пользователей в память, как это
// делает python-версия (notify_roles перебирает всю таблицу).
func (r *Repo) UserIDsByRoles(ctx context.Context, roles []string) ([]int64, error) {
	if len(roles) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id FROM "user" WHERE is_active AND roles ?| $1`, roles)
	if err != nil {
		return nil, fmt.Errorf("поиск получателей по ролям: %w", err)
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
