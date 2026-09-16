// Package repo — репозиторий поверх pgx, без ORM (см. docs/migration-to-go.md).
// Пока — минимальный набор операций для основной агрегации (package →
// package_version → moderation_request → request_item → pipeline_step),
// достаточный, чтобы pipeline runner (следующая фаза) было на чём писать и
// проверять. Расширяется по мере переноса остальных возможностей.
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/domain"
)

// scanner — общий интерфейс для pgx.Row (QueryRow) и pgx.Rows (Query), чтобы
// одна и та же функция сканирования строки работала для обоих случаев.
type scanner interface {
	Scan(dest ...any) error
}

type Repo struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

// jsonOrNull маршалит значение в JSON-строку для передачи в параметр `$N::jsonb`;
// nil/пустой слайс кодируется как SQL NULL, а не как JSON null — отличать
// "поле не заполнено" от "пустой список" явно.
func jsonOrNull(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("сериализация JSONB: %w", err)
	}
	return string(b), nil
}

func unmarshalInto[T any](raw []byte, dst *T) error {
	if raw == nil {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("разбор JSONB: %w", err)
	}
	return nil
}

// GetOrCreatePackage — по (manager, name); DisplayName обновляется только при
// создании (порт поведения Python-версии: display_name — "как заявил
// разработчик", не перезаписывается повторными заявками на ту же нормализацию).
func (r *Repo) GetOrCreatePackage(ctx context.Context, manager, name, displayName string) (*domain.Package, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO package (manager, name, display_name)
		VALUES ($1, $2, $3)
		ON CONFLICT (manager, name) DO UPDATE SET manager = EXCLUDED.manager
		RETURNING id, manager, name, display_name, confirmed_license_spdx,
		          confirmed_license_version, created_at, updated_at
	`, manager, name, displayName)
	return scanPackage(row)
}

func (r *Repo) GetPackage(ctx context.Context, id int64) (*domain.Package, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, manager, name, display_name, confirmed_license_spdx,
		       confirmed_license_version, created_at, updated_at
		FROM package WHERE id = $1
	`, id)
	return scanPackage(row)
}

func scanPackage(row pgx.Row) (*domain.Package, error) {
	var p domain.Package
	if err := row.Scan(
		&p.ID, &p.Manager, &p.Name, &p.DisplayName, &p.ConfirmedLicenseSPDX,
		&p.ConfirmedLicenseVersion, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("чтение package: %w", err)
	}
	return &p, nil
}

// CreatePackageVersion — версия всегда заводится в статусе "new"; переход по
// конвейеру делает pipeline runner, не репозиторий.
func (r *Repo) CreatePackageVersion(ctx context.Context, packageID int64, version, rawVersion string) (*domain.PackageVersion, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO package_version (package_id, version, raw_version, status)
		VALUES ($1, $2, $3, 'new')
		ON CONFLICT (package_id, version) DO UPDATE SET package_id = EXCLUDED.package_id
		RETURNING id, package_id, version, raw_version, status, published_at,
		          quarantine_until, license_spdx, license_source, license_raw,
		          vuln_index_version_id, max_vuln_score, security_override_at,
		          security_override_by_id, security_override_comment,
		          approved_at, revoked_at, status_reason, created_at, updated_at
	`, packageID, version, rawVersion)
	return scanPackageVersion(row)
}

func (r *Repo) GetPackageVersion(ctx context.Context, id int64) (*domain.PackageVersion, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, package_id, version, raw_version, status, published_at,
		       quarantine_until, license_spdx, license_source, license_raw,
		       vuln_index_version_id, max_vuln_score, security_override_at,
		       security_override_by_id, security_override_comment,
		       approved_at, revoked_at, status_reason, created_at, updated_at
		FROM package_version WHERE id = $1
	`, id)
	return scanPackageVersion(row)
}

func scanPackageVersion(row pgx.Row) (*domain.PackageVersion, error) {
	var v domain.PackageVersion
	if err := row.Scan(
		&v.ID, &v.PackageID, &v.Version, &v.RawVersion, &v.Status, &v.PublishedAt,
		&v.QuarantineUntil, &v.LicenseSPDX, &v.LicenseSource, &v.LicenseRaw,
		&v.VulnIndexVersionID, &v.MaxVulnScore, &v.SecurityOverrideAt,
		&v.SecurityOverrideByID, &v.SecurityOverrideComment,
		&v.ApprovedAt, &v.RevokedAt, &v.StatusReason, &v.CreatedAt, &v.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("чтение package_version: %w", err)
	}
	return &v, nil
}

// UpdatePackageVersionStatus — точечное обновление статуса, как делает каждый
// шаг конвейера в Python-версии (не полный UPDATE всей строки).
func (r *Repo) UpdatePackageVersionStatus(ctx context.Context, id int64, status string, reason *string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version SET status = $2, status_reason = $3, updated_at = now()
		WHERE id = $1
	`, id, status, reason)
	if err != nil {
		return fmt.Errorf("обновление статуса package_version: %w", err)
	}
	return nil
}

// UpdatePackageVersionQuarantine — точечное обновление статуса + срока
// карантина, как делает шаг QuarantineStep (не полный UPDATE строки).
func (r *Repo) UpdatePackageVersionQuarantine(ctx context.Context, id int64, status string, quarantineUntil *time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE package_version SET status = $2, quarantine_until = $3, updated_at = now()
		WHERE id = $1
	`, id, status, quarantineUntil)
	if err != nil {
		return fmt.Errorf("обновление карантина package_version: %w", err)
	}
	return nil
}

// UpdateRequestItemStatus — точечное обновление статуса пакета в заявке после
// шага конвейера (аналог присваивания полей `item.status`/`next_action`/
// `blocked_reason` в decisions.py/steps.py Python-версии).
func (r *Repo) UpdateRequestItemStatus(ctx context.Context, id int64, status string, currentStep, blockedReason, nextAction *string, waitingSince *time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE request_item SET
			status = $2, current_step = $3, blocked_reason = $4, next_action = $5,
			waiting_since = $6, updated_at = now()
		WHERE id = $1
	`, id, status, currentStep, blockedReason, nextAction, waitingSince)
	if err != nil {
		return fmt.Errorf("обновление статуса request_item: %w", err)
	}
	return nil
}

func (r *Repo) CreateModerationRequest(ctx context.Context, req domain.ModerationRequest) (*domain.ModerationRequest, error) {
	warnings, err := jsonOrNull(req.Warnings)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO moderation_request
			(author_id, author_role, manager, reason, status, source,
			 idempotency_key, origin_file, include_transitive, warnings)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
		RETURNING id, author_id, author_role, manager, reason, status, source,
		          idempotency_key, origin_file, include_transitive, warnings,
		          created_at, updated_at
	`, req.AuthorID, req.AuthorRole, req.Manager, req.Reason, req.Status, req.Source,
		req.IdempotencyKey, req.OriginFile, req.IncludeTransitive, warnings)
	return scanModerationRequest(row)
}

// GetModerationRequest — заявка по номеру. nil, если такой нет: «заявки не
// существует» — штатный ответ API (404), а не сбой чтения, и отличать одно от
// другого обязан вызывающий, а не текст ошибки.
func (r *Repo) GetModerationRequest(ctx context.Context, id int64) (*domain.ModerationRequest, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, author_id, author_role, manager, reason, status, source,
		       idempotency_key, origin_file, include_transitive, warnings,
		       created_at, updated_at
		FROM moderation_request WHERE id = $1
	`, id)
	req, err := scanModerationRequest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return req, err
}

// GetModerationRequestByIdempotencyKey — реализует контракт "повтор с тем же
// Idempotency-Key не создаёт дубль" (docs/user-stories.md, CI/автоматизация).
func (r *Repo) GetModerationRequestByIdempotencyKey(ctx context.Context, key string) (*domain.ModerationRequest, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, author_id, author_role, manager, reason, status, source,
		       idempotency_key, origin_file, include_transitive, warnings,
		       created_at, updated_at
		FROM moderation_request WHERE idempotency_key = $1
	`, key)
	req, err := scanModerationRequest(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return req, nil
}

func scanModerationRequest(row pgx.Row) (*domain.ModerationRequest, error) {
	var req domain.ModerationRequest
	var warningsRaw []byte
	if err := row.Scan(
		&req.ID, &req.AuthorID, &req.AuthorRole, &req.Manager, &req.Reason, &req.Status,
		&req.Source, &req.IdempotencyKey, &req.OriginFile, &req.IncludeTransitive, &warningsRaw,
		&req.CreatedAt, &req.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("чтение moderation_request: %w", err)
	}
	if err := unmarshalInto(warningsRaw, &req.Warnings); err != nil {
		return nil, err
	}
	return &req, nil
}

func (r *Repo) CreateRequestItem(ctx context.Context, item domain.RequestItem) (*domain.RequestItem, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO request_item
			(request_id, package_version_id, requested_name, requested_version,
			 dependency_kind, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, request_id, package_version_id, requested_name, requested_version,
		          dependency_kind, status, current_step, next_action, blocked_reason,
		          waiting_since, finished_at, created_at, updated_at
	`, item.RequestID, item.PackageVersionID, item.RequestedName, item.RequestedVersion,
		item.DependencyKind, item.Status)
	return scanRequestItem(row)
}

func (r *Repo) GetRequestItem(ctx context.Context, id int64) (*domain.RequestItem, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, request_id, package_version_id, requested_name, requested_version,
		       dependency_kind, status, current_step, next_action, blocked_reason,
		       waiting_since, finished_at, created_at, updated_at
		FROM request_item WHERE id = $1
	`, id)
	return scanRequestItem(row)
}

// ListItemsByRequest — все пакеты заявки, в порядке заведения (порт
// ModerationRequest.items relationship, order_by=RequestItem.id).
func (r *Repo) ListItemsByRequest(ctx context.Context, requestID int64) ([]domain.RequestItem, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, request_id, package_version_id, requested_name, requested_version,
		       dependency_kind, status, current_step, next_action, blocked_reason,
		       waiting_since, finished_at, created_at, updated_at
		FROM request_item WHERE request_id = $1 ORDER BY id
	`, requestID)
	if err != nil {
		return nil, fmt.Errorf("чтение request_item по заявке: %w", err)
	}
	defer rows.Close()

	var items []domain.RequestItem
	for rows.Next() {
		item, err := scanRequestItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

// ListItemsByPackageVersion — все заявки (через request_item), ссылающиеся на
// одну версию пакета. Основа для siblings_awaiting/_apply_to_siblings —
// кросс-заявочного распространения решений (docs/architecture.md,
// "Решение снимает блокировку не только для той заявки, где было нажато").
func (r *Repo) ListItemsByPackageVersion(ctx context.Context, packageVersionID int64) ([]domain.RequestItem, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, request_id, package_version_id, requested_name, requested_version,
		       dependency_kind, status, current_step, next_action, blocked_reason,
		       waiting_since, finished_at, created_at, updated_at
		FROM request_item WHERE package_version_id = $1 ORDER BY id
	`, packageVersionID)
	if err != nil {
		return nil, fmt.Errorf("чтение request_item по версии пакета: %w", err)
	}
	defer rows.Close()

	var items []domain.RequestItem
	for rows.Next() {
		item, err := scanRequestItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

func scanRequestItem(row scanner) (*domain.RequestItem, error) {
	var item domain.RequestItem
	if err := row.Scan(
		&item.ID, &item.RequestID, &item.PackageVersionID, &item.RequestedName,
		&item.RequestedVersion, &item.DependencyKind, &item.Status, &item.CurrentStep,
		&item.NextAction, &item.BlockedReason, &item.WaitingSince, &item.FinishedAt,
		&item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("чтение request_item: %w", err)
	}
	return &item, nil
}

// UpsertPipelineStep — создаёт или обновляет строку шага (уникальность
// (request_item_id, step_code) — повторная вставка того же шага обновляет
// результат, не плодит дубли; так же ведёт себя ORM-версия через merge-паттерн
// в pipeline runner).
func (r *Repo) UpsertPipelineStep(ctx context.Context, step domain.PipelineStep) (*domain.PipelineStep, error) {
	details, err := jsonOrNull(step.Details)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO pipeline_step
			(request_item_id, step_code, step_order, result, message, details, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
		ON CONFLICT (request_item_id, step_code) DO UPDATE SET
			result = EXCLUDED.result,
			message = EXCLUDED.message,
			details = EXCLUDED.details,
			started_at = COALESCE(pipeline_step.started_at, EXCLUDED.started_at),
			finished_at = EXCLUDED.finished_at
		RETURNING id, request_item_id, step_code, step_order, result, message, details,
		          started_at, finished_at
	`, step.RequestItemID, step.StepCode, step.StepOrder, step.Result, step.Message,
		details, step.StartedAt, step.FinishedAt)
	return scanPipelineStep(row)
}

// ListStepsByItem — все шаги пакета в порядке конвейера (порт RequestItem.steps
// relationship, order_by=PipelineStep.step_order).
func (r *Repo) ListStepsByItem(ctx context.Context, requestItemID int64) ([]domain.PipelineStep, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, request_item_id, step_code, step_order, result, message, details,
		       started_at, finished_at
		FROM pipeline_step WHERE request_item_id = $1 ORDER BY step_order
	`, requestItemID)
	if err != nil {
		return nil, fmt.Errorf("чтение pipeline_step по пакету: %w", err)
	}
	defer rows.Close()

	var steps []domain.PipelineStep
	for rows.Next() {
		step, err := scanPipelineStep(rows)
		if err != nil {
			return nil, err
		}
		steps = append(steps, *step)
	}
	return steps, rows.Err()
}

func scanPipelineStep(row scanner) (*domain.PipelineStep, error) {
	var s domain.PipelineStep
	var detailsRaw []byte
	if err := row.Scan(
		&s.ID, &s.RequestItemID, &s.StepCode, &s.StepOrder, &s.Result, &s.Message,
		&detailsRaw, &s.StartedAt, &s.FinishedAt,
	); err != nil {
		return nil, fmt.Errorf("чтение pipeline_step: %w", err)
	}
	if err := unmarshalInto(detailsRaw, &s.Details); err != nil {
		return nil, err
	}
	return &s, nil
}
