// Package config читает конфигурацию сервиса из переменных окружения.
//
// Паттерн — как в sentrix (internal/config): Load собирает ВСЕ ошибки валидации
// разом через errors.Join, не падает на первой. В Python-версии это давалось
// бесплатно pydantic_settings; в Go так само по себе не происходит — нужно
// явно копить []error, см. docs/development-standards.md.
package config

import (
	"errors"
	"fmt"
	"strings"
)

// Config — конфигурация сервиса. Список переменных растёт по мере переноса
// возможностей из backend/app/core/config.py (см. docs/migration-to-go.md) —
// в этой ревизии есть только то, что нужно для каркаса (HTTP + подключение к БД).
type Config struct {
	AppEnv      string // dev | prod — влияет на строгость проверок, как в Python-версии
	ListenAddr  string
	DatabaseURL string
}

// Load читает конфигурацию через getenv (не os.Getenv напрямую — тестируемость,
// тот же приём, что в sentrix).
func Load(getenv func(string) string) (*Config, error) {
	var errs []error

	cfg := &Config{
		AppEnv:      valueOr(getenv("APP_ENV"), "dev"),
		ListenAddr:  valueOr(getenv("LISTEN_ADDR"), ":8000"),
		DatabaseURL: getenv("DATABASE_URL"),
	}

	if cfg.AppEnv != "dev" && cfg.AppEnv != "prod" {
		errs = append(errs, fmt.Errorf("APP_ENV: недопустимое значение %q, ожидается dev или prod", cfg.AppEnv))
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		errs = append(errs, errors.New("DATABASE_URL: не задан — подключение к Postgres невозможно"))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("конфигурация невалидна (%d ошибок): %w", len(errs), errors.Join(errs...))
	}
	return cfg, nil
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
