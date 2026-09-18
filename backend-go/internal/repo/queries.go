package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

// Запросы чтения для API. Отдельно от repo.go: там операции, которыми
// пользуется конвейер (точечные обновления одной строки), здесь — выборки под
// экраны интерфейса, со склейками и постраничностью.
//
// Ни один из них не читает «всё, а лишнее отбросим в Go»: список заявок с
// подсчётом пакетов по статусам делается в SQL. Python-версия делает это
// в памяти (`len(req.items)`, `sum(...)` по связям), и на заявке в 200 пакетов
// это лишние двести строк на каждую строку списка.

// VersionRow — версия пакета вместе с данными самого пакета. Склейка сделана
// в запросе: карточке всегда нужно и то, и другое.
type VersionRow struct {
	Version     domain.PackageVersion
	Manager     string
	Name        string // нормализованное
	DisplayName string
}

const versionSelect = `
	SELECT pv.id, pv.package_id, pv.version, pv.raw_version, pv.status, pv.published_at,
	       pv.quarantine_until, pv.license_spdx, pv.license_source, pv.license_raw,
	       pv.vuln_index_version_id, pv.max_vuln_score, pv.security_override_at,
	       pv.security_override_by_id, pv.security_override_comment,
	       pv.approved_at, pv.revoked_at, pv.status_reason, pv.created_at, pv.updated_at,
	       p.manager, p.name, p.display_name
	FROM package_version pv
	JOIN package p ON p.id = pv.package_id`

func scanVersionRow(row scanner) (*VersionRow, error) {
	var out VersionRow
	v := &out.Version
	if err := row.Scan(
		&v.ID, &v.PackageID, &v.Version, &v.RawVersion, &v.Status, &v.PublishedAt,
		&v.QuarantineUntil, &v.LicenseSPDX, &v.LicenseSource, &v.LicenseRaw,
		&v.VulnIndexVersionID, &v.MaxVulnScore, &v.SecurityOverrideAt,
		&v.SecurityOverrideByID, &v.SecurityOverrideComment,
		&v.ApprovedAt, &v.RevokedAt, &v.StatusReason, &v.CreatedAt, &v.UpdatedAt,
		&out.Manager, &out.Name, &out.DisplayName,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetVersionRow — карточка версии пакета. nil, если такой версии нет.
func (r *Repo) GetVersionRow(ctx context.Context, id int64) (*VersionRow, error) {
	out, err := scanVersionRow(r.pool.QueryRow(ctx, versionSelect+` WHERE pv.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение версии пакета #%d: %w", id, err)
	}
	return out, nil
}

// VersionSearch — параметры поиска по базе пакетов.
type VersionSearch struct {
	Query   string
	Manager string
	Version string
	Status  string
	Limit   int
	Offset  int
}

// SearchVersions — поиск по базе пакетов. Возвращает страницу и общее число
// совпадений: интерфейсу нужно и то, и другое, а два похожих запроса с
// разъезжающимися условиями — верный способ показать «найдено 40» над
// страницей из 50 строк.
func (r *Repo) SearchVersions(ctx context.Context, s VersionSearch) ([]VersionRow, int, error) {
	where, args := versionSearchWhere(s)

	var total int
	countSQL := `SELECT count(*) FROM package_version pv JOIN package p ON p.id = pv.package_id` + where
	if err := r.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("подсчёт пакетов: %w", err)
	}

	limit := s.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := s.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	querySQL := fmt.Sprintf(`%s%s ORDER BY p.name, pv.id DESC LIMIT $%d OFFSET $%d`,
		versionSelect, where, len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("поиск пакетов: %w", err)
	}
	defer rows.Close()

	var out []VersionRow
	for rows.Next() {
		item, err := scanVersionRow(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("чтение строки пакета: %w", err)
		}
		out = append(out, *item)
	}
	return out, total, rows.Err()
}

// versionSearchWhere собирает условие и аргументы. Условия для страницы и для
// счётчика строятся здесь один раз — иначе они неизбежно разойдутся.
func versionSearchWhere(s VersionSearch) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, value any) {
		args = append(args, value)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if q := strings.TrimSpace(s.Query); q != "" {
		// LIKE по неэкранированному вводу: % и _ от пользователя иначе
		// превращают поиск «100%_cov» в выборку всей базы.
		args = append(args, "%"+escapeLike(strings.ToLower(q))+"%")
		conds = append(conds, fmt.Sprintf(
			`(lower(p.name) LIKE $%d ESCAPE '\' OR lower(p.display_name) LIKE $%d ESCAPE '\')`,
			len(args), len(args)))
	}
	if s.Manager != "" {
		add(`p.manager = $%d`, s.Manager)
	}
	if v := strings.TrimSpace(s.Version); v != "" {
		args = append(args, escapeLike(v)+"%")
		conds = append(conds, fmt.Sprintf(`pv.version LIKE $%d ESCAPE '\'`, len(args)))
	}
	if s.Status != "" {
		add(`pv.status = $%d`, s.Status)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// escapeLike экранирует спецсимволы LIKE. Без него поиск по «_» совпадает с
// любым символом, а по «%» — с чем угодно.
func escapeLike(v string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(v)
}

// ListVulnerabilities — уязвимости версии, самые тяжёлые первыми.
func (r *Repo) ListVulnerabilities(ctx context.Context, packageVersionID int64) ([]domain.Vulnerability, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, package_version_id, external_id, aliases, summary, cvss_vector, cvss_score,
		       score, severity, url, affected_ranges, fixed_versions, vuln_index_version_id, detected_at
		FROM vulnerability WHERE package_version_id = $1
		ORDER BY score DESC, external_id
	`, packageVersionID)
	if err != nil {
		return nil, fmt.Errorf("чтение уязвимостей: %w", err)
	}
	defer rows.Close()

	var out []domain.Vulnerability
	for rows.Next() {
		var v domain.Vulnerability
		var aliases, ranges, fixed []byte
		if err := rows.Scan(&v.ID, &v.PackageVersionID, &v.ExternalID, &aliases, &v.Summary,
			&v.CVSSVector, &v.CVSSScore, &v.Score, &v.Severity, &v.URL, &ranges, &fixed,
			&v.VulnIndexVersionID, &v.DetectedAt); err != nil {
			return nil, fmt.Errorf("чтение строки уязвимости: %w", err)
		}
		if err := unmarshalInto(aliases, &v.Aliases); err != nil {
			return nil, err
		}
		if err := unmarshalInto(ranges, &v.AffectedRanges); err != nil {
			return nil, err
		}
		if err := unmarshalInto(fixed, &v.FixedVersions); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LatestItemForVersion — самая свежая заявка по версии пакета. Нужна, чтобы
// на вопрос «почему нельзя ставить» ответить номером уже существующей заявки,
// а не предложением завести вторую.
func (r *Repo) LatestItemForVersion(ctx context.Context, packageVersionID int64) (*domain.RequestItem, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, request_id, package_version_id, requested_name, requested_version,
		       dependency_kind, parent_item_id, depth, required_range, status,
		       current_step, next_action, blocked_reason,
		       waiting_since, finished_at, created_at, updated_at
		FROM request_item WHERE package_version_id = $1 ORDER BY id DESC LIMIT 1
	`, packageVersionID)
	item, err := scanRequestItem(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение заявки по версии: %w", err)
	}
	return item, nil
}

// --------------------------------------------------------------------------- заявки

// RequestListRow — строка списка заявок. Счётчики считаются в SQL, а не
// вычитыванием пакетов в память: в заявке их до двухсот, и на списке из
// пятидесяти заявок это десять тысяч лишних строк.
type RequestListRow struct {
	Request  domain.ModerationRequest
	Author   *string
	Total    int
	Approved int
}

// RequestFilter — фильтры списка заявок.
type RequestFilter struct {
	// AuthorID != nil — показывать только заявки этого автора. Так
	// разработчик видит свои, а DevSecOps/юрист/админ — все.
	AuthorID *int64
	Status   string
	Manager  string
	Limit    int
	Offset   int
}

// ListRequests — список заявок с учётом прав и фильтров.
func (r *Repo) ListRequests(ctx context.Context, f RequestFilter) ([]RequestListRow, error) {
	var conds []string
	var args []any
	add := func(cond string, value any) {
		args = append(args, value)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.AuthorID != nil {
		add(`mr.author_id = $%d`, *f.AuthorID)
	}
	if f.Status != "" {
		add(`mr.status = $%d`, f.Status)
	}
	if f.Manager != "" {
		add(`mr.manager = $%d`, f.Manager)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)

	query := fmt.Sprintf(`
		SELECT mr.id, mr.author_id, mr.author_role, mr.manager, mr.reason, mr.status,
		       mr.source, mr.idempotency_key, mr.origin_file, mr.include_transitive,
		       mr.warnings, mr.created_at, mr.updated_at,
		       u.username,
		       (SELECT count(*) FROM request_item ri WHERE ri.request_id = mr.id),
		       (SELECT count(*) FROM request_item ri
		         WHERE ri.request_id = mr.id AND ri.status = 'approved')
		FROM moderation_request mr
		LEFT JOIN "user" u ON u.id = mr.author_id%s
		ORDER BY mr.id DESC LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("чтение списка заявок: %w", err)
	}
	defer rows.Close()

	var out []RequestListRow
	for rows.Next() {
		var item RequestListRow
		req := &item.Request
		var warnings []byte
		if err := rows.Scan(&req.ID, &req.AuthorID, &req.AuthorRole, &req.Manager, &req.Reason,
			&req.Status, &req.Source, &req.IdempotencyKey, &req.OriginFile, &req.IncludeTransitive,
			&warnings, &req.CreatedAt, &req.UpdatedAt,
			&item.Author, &item.Total, &item.Approved); err != nil {
			return nil, fmt.Errorf("чтение строки списка заявок: %w", err)
		}
		if err := unmarshalInto(warnings, &req.Warnings); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// AuthorOf — логин автора заявки. Пустая строка, если автор удалён: заявка
// при этом остаётся читаемой.
func (r *Repo) AuthorOf(ctx context.Context, requestID int64) (string, error) {
	var username *string
	err := r.pool.QueryRow(ctx, `
		SELECT u.username FROM moderation_request mr
		LEFT JOIN "user" u ON u.id = mr.author_id WHERE mr.id = $1
	`, requestID).Scan(&username)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("чтение автора заявки: %w", err)
	}
	if username == nil {
		return "", nil
	}
	return *username, nil
}

// StepsByItems — шаги сразу по всем пакетам заявки, одним запросом.
// Возвращает карту item_id -> шаги в порядке конвейера.
func (r *Repo) StepsByItems(ctx context.Context, itemIDs []int64) (map[int64][]domain.PipelineStep, error) {
	out := map[int64][]domain.PipelineStep{}
	if len(itemIDs) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, request_item_id, step_code, step_order, result, message, details,
		       started_at, finished_at
		FROM pipeline_step WHERE request_item_id = ANY($1) ORDER BY request_item_id, step_order
	`, itemIDs)
	if err != nil {
		return nil, fmt.Errorf("чтение шагов по пакетам заявки: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		step, err := scanPipelineStep(rows)
		if err != nil {
			return nil, err
		}
		out[step.RequestItemID] = append(out[step.RequestItemID], *step)
	}
	return out, rows.Err()
}

// VersionsByIDs — версии пакетов сразу по списку идентификаторов.
func (r *Repo) VersionsByIDs(ctx context.Context, ids []int64) (map[int64]VersionRow, error) {
	out := map[int64]VersionRow{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, versionSelect+` WHERE pv.id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("чтение версий пакетов: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanVersionRow(rows)
		if err != nil {
			return nil, fmt.Errorf("чтение строки версии пакета: %w", err)
		}
		out[item.Version.ID] = *item
	}
	return out, rows.Err()
}

// VulnerabilitiesByVersions — уязвимости сразу по списку версий.
func (r *Repo) VulnerabilitiesByVersions(ctx context.Context, ids []int64) (map[int64][]domain.Vulnerability, error) {
	out := map[int64][]domain.Vulnerability{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, package_version_id, external_id, aliases, summary, cvss_vector, cvss_score,
		       score, severity, url, affected_ranges, fixed_versions, vuln_index_version_id, detected_at
		FROM vulnerability WHERE package_version_id = ANY($1)
		ORDER BY package_version_id, score DESC, external_id
	`, ids)
	if err != nil {
		return nil, fmt.Errorf("чтение уязвимостей по версиям: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v domain.Vulnerability
		var aliases, ranges, fixed []byte
		if err := rows.Scan(&v.ID, &v.PackageVersionID, &v.ExternalID, &aliases, &v.Summary,
			&v.CVSSVector, &v.CVSSScore, &v.Score, &v.Severity, &v.URL, &ranges, &fixed,
			&v.VulnIndexVersionID, &v.DetectedAt); err != nil {
			return nil, fmt.Errorf("чтение строки уязвимости: %w", err)
		}
		if err := unmarshalInto(aliases, &v.Aliases); err != nil {
			return nil, err
		}
		if err := unmarshalInto(ranges, &v.AffectedRanges); err != nil {
			return nil, err
		}
		if err := unmarshalInto(fixed, &v.FixedVersions); err != nil {
			return nil, err
		}
		out[v.PackageVersionID] = append(out[v.PackageVersionID], v)
	}
	return out, rows.Err()
}

// CodeFindingsByVersions — находки сканеров содержимого сразу по списку версий.
// Порядок — как в python-версии: по сканеру, затем по файлу.
func (r *Repo) CodeFindingsByVersions(ctx context.Context, ids []int64) (map[int64][]domain.CodeFinding, error) {
	out := map[int64][]domain.CodeFinding{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, package_version_id, scanner, rule_id, severity, message, file_path,
		       line, matched, detected_at
		FROM code_finding WHERE package_version_id = ANY($1)
		ORDER BY package_version_id, scanner, coalesce(file_path, ''), id
	`, ids)
	if err != nil {
		return nil, fmt.Errorf("чтение находок по версиям: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f domain.CodeFinding
		if err := rows.Scan(&f.ID, &f.PackageVersionID, &f.Scanner, &f.RuleID, &f.Severity,
			&f.Message, &f.FilePath, &f.Line, &f.Matched, &f.DetectedAt); err != nil {
			return nil, fmt.Errorf("чтение строки находки: %w", err)
		}
		out[f.PackageVersionID] = append(out[f.PackageVersionID], f)
	}
	return out, rows.Err()
}

// FindVersion — версия пакета по менеджеру, нормализованному имени и
// нормализованной версии. nil, если такой в базе нет.
//
// Сверка идёт по нормализованным значениям, а не по тому, как их записал
// разработчик: «Django» и «django», «1.0» и «1.0.0» — один и тот же пакет, и
// заводить на них разные строки значило бы модерировать одно дважды.
func (r *Repo) FindVersion(ctx context.Context, manager, name, version string) (*domain.PackageVersion, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT pv.id, pv.package_id, pv.version, pv.raw_version, pv.status, pv.published_at,
		       pv.quarantine_until, pv.license_spdx, pv.license_source, pv.license_raw,
		       pv.vuln_index_version_id, pv.max_vuln_score, pv.security_override_at,
		       pv.security_override_by_id, pv.security_override_comment,
		       pv.approved_at, pv.revoked_at, pv.status_reason, pv.created_at, pv.updated_at
		FROM package_version pv
		JOIN package p ON p.id = pv.package_id
		WHERE p.manager = $1 AND p.name = $2 AND pv.version = $3
	`, manager, name, version)
	version_, err := scanPackageVersion(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return version_, nil
}

// RecomputeRequestStatus пересчитывает статус заявки по статусам её пакетов.
// Порт runner.recompute_request_status.
//
// Считается в SQL одним запросом: статусы пакетов нужны только для этой
// свёртки, и вычитывать двести строк в память ради неё незачем. Порядок веток
// — по убыванию «блокирующей силы», как в python-версии: пока хоть один пакет
// в работе, заявка целиком «в обработке», каким бы ни был вердикт остальных.
func (r *Repo) RecomputeRequestStatus(ctx context.Context, requestID int64) (string, error) {
	var status string
	row := r.pool.QueryRow(ctx, `
		WITH all_items AS (SELECT status FROM request_item WHERE request_id = $1),
		-- Отменённые пакеты в свёртке не участвуют: автор сказал, что они не
		-- нужны, и тянуть из-за них заявку в «отклонена» неверно. Если
		-- отменены все — заявка отменена, это первая ветка ниже.
		s AS (SELECT status FROM all_items WHERE status <> 'cancelled')
		UPDATE moderation_request mr
		SET status = CASE
			WHEN NOT EXISTS (SELECT 1 FROM all_items) THEN 'pending'
			WHEN NOT EXISTS (SELECT 1 FROM s) THEN 'cancelled'
			WHEN EXISTS (SELECT 1 FROM s WHERE status IN ('queued', 'running')) THEN 'pending'
			WHEN EXISTS (SELECT 1 FROM s WHERE status = 'awaiting_security') THEN 'awaiting_security'
			WHEN EXISTS (SELECT 1 FROM s WHERE status IN ('awaiting_legal', 'license_claimed'))
				THEN 'awaiting_legal'
			WHEN EXISTS (SELECT 1 FROM s WHERE status = 'quarantined') THEN 'quarantined'
			WHEN NOT EXISTS (SELECT 1 FROM s WHERE status <> 'approved') THEN 'approved'
			-- Все пакеты прошли в режиме «без записи»: проверка выполнена
			-- целиком, но публикации не было. Ни approved (команда установки
			-- вела бы в никуда), ни rejected (ничего не отклоняли).
			WHEN NOT EXISTS (SELECT 1 FROM s WHERE status NOT IN ('approved', 'dry_run'))
				THEN 'dry_run'
			WHEN EXISTS (SELECT 1 FROM s WHERE status = 'approved') THEN 'partially_approved'
			WHEN EXISTS (SELECT 1 FROM s WHERE status = 'failed') THEN 'failed'
			ELSE 'rejected'
		END,
		updated_at = now()
		WHERE mr.id = $1
		RETURNING mr.status
	`, requestID)
	if err := row.Scan(&status); err != nil {
		return "", fmt.Errorf("пересчёт статуса заявки #%d: %w", requestID, err)
	}
	return status, nil
}

// CancellableItemStatuses — из каких статусов пакет можно отменить.
//
// Отмена — не отзыв решения: пакет, по которому вердикт уже вынесен
// (одобрен, отклонён, отозван, запрещён), не отменяется — для снятия
// опубликованного есть revoke. `failed` отменить можно: техническая ошибка
// это не вердикт, и автор вправе сказать «уже не надо» вместо перезапуска.
var CancellableItemStatuses = []string{
	"queued", "running", "quarantined", "awaiting_legal", "license_claimed",
	"awaiting_security", "failed",
}

// CancelRequestItems отменяет пакеты заявки и возвращает число отменённых.
//
// Одним запросом: между «посмотреть, что можно отменить» и «отменить» пакет
// мог уйти воркеру или получить решение роли, и отменять его тогда нельзя.
// Условие по статусу стоит в самом UPDATE, поэтому гонка невозможна — так же,
// как в захвате очереди.
//
// Пакет в статусе `running` отменяется тоже: прогон это заметит. Отметка о
// жизни (Queue.Heartbeat) обновляет строку только пока она `running`, и
// увидев, что строку «отобрали», воркер прекращает прогон — дописывать шаги
// отменённого пакета незачем. Публикация защищена отдельно, в самом шаге.
func (r *Repo) CancelRequestItems(ctx context.Context, requestID int64) (int, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE request_item
		SET status = 'cancelled', finished_at = now(), updated_at = now(),
		    waiting_since = NULL, next_action = NULL,
		    blocked_reason = 'Заявка закрыта автором: пакет больше не нужен',
		    resume_from_step = NULL
		WHERE request_id = $1 AND status = ANY($2)
	`, requestID, CancellableItemStatuses)
	if err != nil {
		return 0, fmt.Errorf("отмена пакетов заявки #%d: %w", requestID, err)
	}
	return int(tag.RowsAffected()), nil
}

// ItemStatusByRequest — статусы пакетов заявки. Нужен маршруту отмены, чтобы
// объяснить, почему отменять нечего: «всё уже одобрено» и «заявка уже
// отменена» — разные ответы.
func (r *Repo) ItemStatusByRequest(ctx context.Context, requestID int64) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT status FROM request_item WHERE request_id = $1 ORDER BY id`, requestID)
	if err != nil {
		return nil, fmt.Errorf("статусы пакетов заявки #%d: %w", requestID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	return out, rows.Err()
}
