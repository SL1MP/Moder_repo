package repo

import (
	"context"
	"fmt"
)

// AppSettingsChannel сообщает долгоживущим процессам, что сохранённые через
// web настройки изменились. NOTIFY выполняется в той же транзакции, что и
// UPDATE: подписчики увидят событие только после успешного COMMIT и загрузят
// уже зафиксированные значения.
const AppSettingsChannel = "moderation_app_settings_changed"

// AppSettings возвращает сохранённые через web переопределения .env.
// Секреты в эту таблицу не пишутся: список допустимых ключей задаёт config.
func (r *Repo) AppSettings(ctx context.Context) (map[string]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT key, value FROM app_setting ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("чтение настроек приложения: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("чтение настройки приложения: %w", err)
		}
		out[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("чтение настроек приложения: %w", err)
	}
	return out, nil
}

// SaveAppSettings атомарно сохраняет набор настроек. Пустой набор допустим.
func (r *Repo) SaveAppSettings(ctx context.Context, values map[string]string, actorID int64) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало сохранения настроек: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for key, value := range values {
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_setting (key, value, updated_by_id, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (key) DO UPDATE SET
				value = EXCLUDED.value,
				updated_by_id = EXCLUDED.updated_by_id,
				updated_at = EXCLUDED.updated_at`, key, value, actorID); err != nil {
			return fmt.Errorf("сохранение настройки %s: %w", key, err)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, '')`, AppSettingsChannel); err != nil {
		return fmt.Errorf("уведомление об изменении настроек: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("фиксация настроек: %w", err)
	}
	return nil
}
