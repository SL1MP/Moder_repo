// Package db открывает пул подключений к Postgres через pgx — без ORM, как в
// sentrix/oakshield (см. docs/migration-to-go.md: "GORM у vumana — единственное
// расхождение референсов, не повторять").
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open создаёт пул подключений и проверяет его одним Ping — чтобы сервис падал
// при старте с понятной ошибкой, а не на первом реальном запросе.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("создание пула подключений к Postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("Postgres недоступен: %w", err)
	}
	return pool, nil
}
