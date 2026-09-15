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

	// Хранилище отчётов и артефактов (карантинная зона). Пустой S3Endpoint —
	// хранилище не настроено: сервис поднимается, но выдача отчётов отключена.
	// Падать на старте из-за отчётов нельзя: health должен отвечать.
	S3Endpoint  string
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string
	S3Region    string
}

// Load читает конфигурацию через getenv (не os.Getenv напрямую — тестируемость,
// тот же приём, что в sentrix).
func Load(getenv func(string) string) (*Config, error) {
	var errs []error

	cfg := &Config{
		AppEnv:      valueOr(getenv("APP_ENV"), "dev"),
		ListenAddr:  valueOr(getenv("LISTEN_ADDR"), ":8000"),
		DatabaseURL: getenv("DATABASE_URL"),
		S3Endpoint:  getenv("S3_ENDPOINT"),
		S3Bucket:    valueOr(getenv("S3_BUCKET"), "moderation-artifacts"),
		S3AccessKey: getenv("S3_ACCESS_KEY"),
		S3SecretKey: getenv("S3_SECRET_KEY"),
		S3Region:    valueOr(getenv("S3_REGION"), "us-east-1"),
	}

	if cfg.AppEnv != "dev" && cfg.AppEnv != "prod" {
		errs = append(errs, fmt.Errorf("APP_ENV: недопустимое значение %q, ожидается dev или prod", cfg.AppEnv))
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		errs = append(errs, errors.New("DATABASE_URL: не задан — подключение к Postgres невозможно"))
	}
	// Хранилище задано наполовину — это почти наверняка опечатка в .env, и
	// молча работать без отчётов здесь хуже, чем сказать об этом на старте.
	if strings.TrimSpace(cfg.S3Endpoint) != "" {
		if strings.TrimSpace(cfg.S3AccessKey) == "" || strings.TrimSpace(cfg.S3SecretKey) == "" {
			errs = append(errs, errors.New(
				"S3_ACCESS_KEY/S3_SECRET_KEY: не заданы при заданном S3_ENDPOINT — хранилище отчётов не настроится"))
		}
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
