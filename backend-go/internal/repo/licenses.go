package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"moderation/internal/policy"
)

// LicenseEntries возвращает web-версию политики. configured=false означает,
// что администратор или юрист ещё не сохранял её и действует licenses.yml.
func (r *Repo) LicenseEntries(ctx context.Context) ([]policy.LicenseEntry, bool, error) {
	if r == nil || r.pool == nil {
		return nil, false, nil
	}
	var raw []byte
	err := r.pool.QueryRow(ctx, `SELECT entries FROM license_policy WHERE id = 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("чтение политики лицензий из базы: %w", err)
	}
	var entries []policy.LicenseEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, false, fmt.Errorf("разбор политики лицензий из базы: %w", err)
	}
	return entries, true, nil
}

// SaveLicenseEntries сохраняет полную политику и будит процессы, чтобы новое
// решение применилось без ручного перезапуска.
func (r *Repo) SaveLicenseEntries(ctx context.Context, entries []policy.LicenseEntry, actorID int64) error {
	raw, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("сериализация политики лицензий: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало сохранения политики лицензий: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO license_policy (id, entries, updated_by_id, updated_at)
		VALUES (1, $1::jsonb, $2, now())
		ON CONFLICT (id) DO UPDATE SET entries = EXCLUDED.entries,
			updated_by_id = EXCLUDED.updated_by_id, updated_at = EXCLUDED.updated_at`,
		string(raw), actorID); err != nil {
		return fmt.Errorf("сохранение политики лицензий: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, '')`, AppSettingsChannel); err != nil {
		return fmt.Errorf("уведомление об изменении политики лицензий: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("фиксация политики лицензий: %w", err)
	}
	return nil
}
