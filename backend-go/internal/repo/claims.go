package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"moderation/internal/domain"
)

// Заявления лицензий: разработчик прикладывает ссылку, юрист по ней решает.

const claimColumns = `lc.id, lc.package_version_id, lc.request_item_id, lc.claimed_by_id, lc.url,
	lc.snapshot_text, lc.snapshot_fetched_at, lc.spdx_id, lc.comment, lc.status,
	lc.decided_by_id, lc.decided_at, lc.decision_comment, lc.created_at, lc.updated_at`

// ClaimRow — заявление вместе с тем, что о нём нужно знать интерфейсу:
// какой это пакет и кто участвовал.
type ClaimRow struct {
	Claim       domain.LicenseClaim
	Manager     string
	PackageName string
	Version     string
	ClaimedBy   *string
	DecidedBy   *string
}

const claimSelect = `
	SELECT ` + claimColumns + `, p.manager, p.display_name, pv.raw_version,
	       claimer.username, decider.username
	FROM license_claim lc
	JOIN package_version pv ON pv.id = lc.package_version_id
	JOIN package p ON p.id = pv.package_id
	LEFT JOIN "user" claimer ON claimer.id = lc.claimed_by_id
	LEFT JOIN "user" decider ON decider.id = lc.decided_by_id`

func scanClaim(row scanner) (*ClaimRow, error) {
	var out ClaimRow
	c := &out.Claim
	if err := row.Scan(&c.ID, &c.PackageVersionID, &c.RequestItemID, &c.ClaimedByID, &c.URL,
		&c.SnapshotText, &c.SnapshotFetchedAt, &c.SPDXID, &c.Comment, &c.Status,
		&c.DecidedByID, &c.DecidedAt, &c.DecisionComment, &c.CreatedAt, &c.UpdatedAt,
		&out.Manager, &out.PackageName, &out.Version, &out.ClaimedBy, &out.DecidedBy); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetLicenseClaim — заявление по идентификатору. nil, если такого нет.
func (r *Repo) GetLicenseClaim(ctx context.Context, id int64) (*ClaimRow, error) {
	row, err := scanClaim(r.pool.QueryRow(ctx, claimSelect+` WHERE lc.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение заявления лицензии #%d: %w", id, err)
	}
	return row, nil
}

// ListLicenseClaims — заявления с фильтром по статусу. claimedBy != nil
// оставляет только свои: разработчик видит свои заявления, роли — все.
func (r *Repo) ListLicenseClaims(ctx context.Context, status string, claimedBy *int64) ([]ClaimRow, error) {
	query := claimSelect
	var conds []string
	var args []any
	if status != "" {
		args = append(args, status)
		conds = append(conds, fmt.Sprintf("lc.status = $%d", len(args)))
	}
	if claimedBy != nil {
		args = append(args, *claimedBy)
		conds = append(conds, fmt.Sprintf("lc.claimed_by_id = $%d", len(args)))
	}
	for i, cond := range conds {
		if i == 0 {
			query += " WHERE " + cond
			continue
		}
		query += " AND " + cond
	}
	query += " ORDER BY lc.id DESC"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("чтение заявлений лицензий: %w", err)
	}
	defer rows.Close()

	var out []ClaimRow
	for rows.Next() {
		item, err := scanClaim(rows)
		if err != nil {
			return nil, fmt.Errorf("чтение строки заявления: %w", err)
		}
		out = append(out, *item)
	}
	return out, rows.Err()
}

// CreateLicenseClaim заводит заявление. Предыдущие незакрытые по той же версии
// закрываются: два открытых заявления на один пакет означали бы, что юрист
// решает дважды одно и то же.
func (r *Repo) CreateLicenseClaim(ctx context.Context, claim domain.LicenseClaim) (*ClaimRow, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("начало транзакции заявления: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE license_claim SET status = 'rejected',
		    decision_comment = 'Заменено более новым заявлением', updated_at = now()
		WHERE package_version_id = $1 AND status = 'pending'
	`, claim.PackageVersionID); err != nil {
		return nil, fmt.Errorf("закрытие прежних заявлений: %w", err)
	}

	var id int64
	err = tx.QueryRow(ctx, `
		INSERT INTO license_claim (package_version_id, request_item_id, claimed_by_id, url,
		                           snapshot_text, snapshot_fetched_at, spdx_id, comment, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
		RETURNING id
	`, claim.PackageVersionID, claim.RequestItemID, claim.ClaimedByID, claim.URL,
		claim.SnapshotText, claim.SnapshotFetchedAt, claim.SPDXID, claim.Comment).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("создание заявления лицензии: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("фиксация заявления: %w", err)
	}
	return r.GetLicenseClaim(ctx, id)
}

// DecideLicenseClaim отмечает решение юриста по заявлению.
func (r *Repo) DecideLicenseClaim(ctx context.Context, id int64, approve bool, actorID int64, comment string, now time.Time) error {
	status := "rejected"
	if approve {
		status = "approved"
	}
	var decisionComment any
	if comment != "" {
		decisionComment = comment
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE license_claim
		SET status = $2, decided_by_id = $3, decided_at = $4, decision_comment = $5, updated_at = $4
		WHERE id = $1 AND status = 'pending'
	`, id, status, actorID, now, decisionComment)
	if err != nil {
		return fmt.Errorf("решение по заявлению #%d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		// Решение по уже закрытому заявлению — не ошибка записи, а конфликт
		// состояния: кто-то решил раньше.
		return fmt.Errorf("%w: по заявлению #%d решение уже принято", ErrAlreadyDecided, id)
	}
	return nil
}

// ErrAlreadyDecided — решение по заявлению уже принято.
var ErrAlreadyDecided = errors.New("решение уже принято")

// SuggestedLicense — лицензия, подтверждённая для этого пакета ранее.
// Пустая строка, если подтверждённой нет.
//
// Нужна юристу: если по другой версии того же пакета лицензия уже
// подтверждена, разбирать её заново незачем.
func (r *Repo) SuggestedLicense(ctx context.Context, packageVersionID int64) (string, string, error) {
	var spdx, version *string
	err := r.pool.QueryRow(ctx, `
		SELECT p.confirmed_license_spdx, p.confirmed_license_version
		FROM package_version pv JOIN package p ON p.id = pv.package_id
		WHERE pv.id = $1
	`, packageVersionID).Scan(&spdx, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("чтение подтверждённой лицензии: %w", err)
	}
	return derefString(spdx), derefString(version), nil
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
