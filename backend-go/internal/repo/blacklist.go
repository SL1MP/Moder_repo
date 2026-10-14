package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"moderation/internal/policy"
)

// BlacklistRules возвращает web-версию blacklist. configured=false означает,
// что администратор ещё ни разу не сохранял правила и источником остаётся
// config/blacklist.yml. Пустой сохранённый массив — намеренная пустая политика,
// поэтому его нельзя смешивать с отсутствующей строкой.
func (r *Repo) BlacklistRules(ctx context.Context) (rules []policy.Rule, configured bool, err error) {
	if r == nil || r.pool == nil {
		return nil, false, nil
	}
	var raw []byte
	err = r.pool.QueryRow(ctx, `SELECT rules FROM blacklist_policy WHERE id = 1`).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("чтение blacklist из базы: %w", err)
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, false, fmt.Errorf("разбор blacklist из базы: %w", err)
	}
	return rules, true, nil
}

// SaveBlacklistRules сохраняет полную версию правил одной транзакцией. После
// COMMIT все экземпляры API и worker получают то же уведомление, что при
// изменении runtime-настроек, и пересобирают зависимости из согласованного
// снимка конфигурации.
func (r *Repo) SaveBlacklistRules(ctx context.Context, rules []policy.Rule, actorID int64) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("подключение к базе не настроено")
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("сериализация blacklist: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало сохранения blacklist: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO blacklist_policy (id, rules, updated_by_id, updated_at)
		VALUES (1, $1::jsonb, $2, now())
		ON CONFLICT (id) DO UPDATE SET
			rules = EXCLUDED.rules,
			updated_by_id = EXCLUDED.updated_by_id,
			updated_at = EXCLUDED.updated_at`, string(raw), actorID); err != nil {
		return fmt.Errorf("сохранение blacklist: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, '')`, AppSettingsChannel); err != nil {
		return fmt.Errorf("уведомление об изменении blacklist: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("фиксация blacklist: %w", err)
	}
	return nil
}
