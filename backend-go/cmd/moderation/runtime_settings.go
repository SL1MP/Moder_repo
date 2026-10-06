package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/config"
	"moderation/internal/repo"
)

// applyStoredSettings накладывает web-настройки поверх .env до создания
// клиентов реестров, артефактори и конвейера. Если миграция ещё не применена,
// процесс продолжает запуск с .env — migrate-go стартует отдельно и первым.
func applyStoredSettings(
	ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, logger *slog.Logger,
) {
	values, err := repo.New(pool).AppSettings(ctx)
	if err != nil {
		logger.Warn("web-настройки не загружены, используются значения .env", "error", err)
		return
	}
	if len(values) == 0 {
		return
	}
	if err := cfg.ApplyOverrides(values); err != nil {
		logger.Error("сохранённые web-настройки невалидны, используются значения .env", "error", err)
		return
	}
	logger.Info("применены web-настройки", "количество", len(values))
}
