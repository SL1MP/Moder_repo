package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

const scanReportColumns = `id, request_item_id, package_version_id, step_code, scanner, rules,
	state, threshold, findings_total, findings_blocking, worst_severity, detail,
	json_key, html_key, bucket, duration_ms, created_at`

// UpsertScanReport — один актуальный отчёт на пару (пакет заявки, шаг):
// повторный прогон обновляет его, а не плодит строки.
func (r *Repo) UpsertScanReport(ctx context.Context, report domain.ScanReport) (*domain.ScanReport, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO scan_report
			(request_item_id, package_version_id, step_code, scanner, rules, state, threshold,
			 findings_total, findings_blocking, worst_severity, detail, json_key, html_key,
			 bucket, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT ON CONSTRAINT uq_scan_report_item_step DO UPDATE SET
			scanner = EXCLUDED.scanner, rules = EXCLUDED.rules, state = EXCLUDED.state,
			threshold = EXCLUDED.threshold, findings_total = EXCLUDED.findings_total,
			findings_blocking = EXCLUDED.findings_blocking, worst_severity = EXCLUDED.worst_severity,
			detail = EXCLUDED.detail, json_key = EXCLUDED.json_key, html_key = EXCLUDED.html_key,
			bucket = EXCLUDED.bucket, duration_ms = EXCLUDED.duration_ms, created_at = now()
		RETURNING `+scanReportColumns, //nolint:gocritic // константа колонок, не пользовательский ввод
		report.RequestItemID, report.PackageVersionID, report.StepCode, report.Scanner,
		report.Rules, report.State, report.Threshold, report.FindingsTotal,
		report.FindingsBlocking, report.WorstSeverity, report.Detail,
		report.JSONKey, report.HTMLKey, report.Bucket, report.DurationMs)
	return scanScanReport(row)
}

// GetScanReport — отчёт по пакету заявки и шагу. nil, если прогона не было.
func (r *Repo) GetScanReport(ctx context.Context, requestItemID int64, stepCode string) (*domain.ScanReport, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+scanReportColumns+` FROM scan_report WHERE request_item_id = $1 AND step_code = $2`,
		requestItemID, stepCode)
	report, err := scanScanReport(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return report, nil
}

// ListScanReports — все отчёты по пакету заявки, в порядке шагов конвейера.
func (r *Repo) ListScanReports(ctx context.Context, requestItemID int64) ([]domain.ScanReport, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+scanReportColumns+` FROM scan_report WHERE request_item_id = $1 ORDER BY step_code`,
		requestItemID)
	if err != nil {
		return nil, fmt.Errorf("чтение отчётов сканирования: %w", err)
	}
	defer rows.Close()

	var out []domain.ScanReport
	for rows.Next() {
		report, err := scanScanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *report)
	}
	return out, rows.Err()
}

func scanScanReport(row scanner) (*domain.ScanReport, error) {
	var s domain.ScanReport
	if err := row.Scan(
		&s.ID, &s.RequestItemID, &s.PackageVersionID, &s.StepCode, &s.Scanner, &s.Rules,
		&s.State, &s.Threshold, &s.FindingsTotal, &s.FindingsBlocking, &s.WorstSeverity,
		&s.Detail, &s.JSONKey, &s.HTMLKey, &s.Bucket, &s.DurationMs, &s.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("чтение scan_report: %w", err)
	}
	return &s, nil
}

// --------------------------------------------------------------------------- пользователи

// GetUser — пользователь по идентификатору. nil, если такого нет: имя
// принявшего решение подставляется в сообщения шагов и в отчёт, и отсутствие
// пользователя не должно ронять конвейер.
func (r *Repo) GetUser(ctx context.Context, id int64) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, subject, username, email, full_name, roles, is_service, is_active,
		       password_hash, last_login_at, created_at, updated_at
		FROM "user" WHERE id = $1
	`, id)
	var u domain.User
	var roles []byte
	if err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.Email, &u.FullName, &roles,
		&u.IsService, &u.IsActive, &u.PasswordHash, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("чтение user: %w", err)
	}
	if err := unmarshalInto(roles, &u.Roles); err != nil {
		return nil, err
	}
	return &u, nil
}

// DisplayName — как назвать пользователя в сообщении: полное имя, иначе логин.
func DisplayName(u *domain.User, fallback string) string {
	if u == nil {
		return fallback
	}
	if u.FullName != nil && *u.FullName != "" {
		return *u.FullName
	}
	if u.Username != "" {
		return u.Username
	}
	return fallback
}

// GetOrCreateUser — пользователь по логину, заводится при отсутствии.
//
// Нужен интеграционным тестам: без него они опирались бы на пользователя,
// заведённого руками (AuthorID: 1), и падали бы на чистой базе или после
// чужого прогона. Это уже случалось — см. handoff, п. 5, пункт 10.
func (r *Repo) GetOrCreateUser(ctx context.Context, username, fullName string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO "user" (username, full_name, roles, is_service, is_active)
		VALUES ($1, $2, '["developer"]'::jsonb, FALSE, TRUE)
		ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
		RETURNING id, subject, username, email, full_name, roles, is_service, is_active,
		          password_hash, last_login_at, created_at, updated_at
	`, username, fullName)

	var u domain.User
	var roles []byte
	if err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.Email, &u.FullName, &roles,
		&u.IsService, &u.IsActive, &u.PasswordHash, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, fmt.Errorf("создание пользователя: %w", err)
	}
	if err := unmarshalInto(roles, &u.Roles); err != nil {
		return nil, err
	}
	return &u, nil
}
