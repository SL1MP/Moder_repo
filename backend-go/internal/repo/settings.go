package repo

import (
	"context"
	"fmt"
	"strings"
)

const encryptedSettingPrefix = "fernet:"

// SettingsCipher шифрует секретные web-настройки. Интерфейс оставляет repo
// независимым от конкретной реализации шифрования.
type SettingsCipher interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

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

// EffectiveAppSettings возвращает значения, пригодные для применения к
// Config. Секреты остаются зашифрованными в Postgres и раскрываются только в
// памяти процесса.
func (r *Repo) EffectiveAppSettings(ctx context.Context, cipher SettingsCipher) (map[string]string, error) {
	values, err := r.AppSettings(ctx)
	if err != nil {
		return nil, err
	}
	for key, value := range values {
		if !strings.HasPrefix(value, encryptedSettingPrefix) {
			continue
		}
		if cipher == nil {
			return nil, fmt.Errorf("расшифровка настройки %s: ключ шифрования не настроен", key)
		}
		plain, err := cipher.Decrypt(strings.TrimPrefix(value, encryptedSettingPrefix))
		if err != nil {
			return nil, fmt.Errorf("расшифровка настройки %s: %w", key, err)
		}
		values[key] = plain
	}
	return values, nil
}

// SaveAppSettings атомарно сохраняет набор настроек. Пустой набор допустим.
func (r *Repo) SaveAppSettings(ctx context.Context, values map[string]string, actorID int64) error {
	return r.SaveAppSettingsSecure(ctx, values, actorID, nil, nil)
}

// SaveAppSettingsSecure атомарно сохраняет настройки. Пустое значение
// секрета означает «оставить прежнее»: браузер никогда не получает секрет
// обратно и потому не должен случайно стереть его при сохранении формы.
func (r *Repo) SaveAppSettingsSecure(
	ctx context.Context, values map[string]string, actorID int64,
	isSecret func(string) bool, cipher SettingsCipher,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало сохранения настроек: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for key, value := range values {
		secret := isSecret != nil && isSecret(key)
		if secret && strings.TrimSpace(value) == "" {
			continue
		}
		stored := value
		if secret {
			if cipher == nil {
				return fmt.Errorf("сохранение настройки %s: ключ шифрования не настроен", key)
			}
			encrypted, err := cipher.Encrypt(value)
			if err != nil {
				return fmt.Errorf("шифрование настройки %s: %w", key, err)
			}
			stored = encryptedSettingPrefix + encrypted
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_setting (key, value, updated_by_id, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (key) DO UPDATE SET
				value = EXCLUDED.value,
				updated_by_id = EXCLUDED.updated_by_id,
				updated_at = EXCLUDED.updated_at`, key, stored, actorID); err != nil {
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
