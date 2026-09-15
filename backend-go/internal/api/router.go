// Package api собирает chi-роутер сервиса. Начинается с health/metrics —
// остальные маршруты (см. docs/api.md) переносятся по мере переноса пайплайна
// и адаптеров, см. docs/migration-to-go.md, "Фазы".
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const pingTimeout = 3 * time.Second

// NewRouter собирает роутер. pool может быть nil в тестах, которые не трогают БД.
func NewRouter(pool *pgxpool.Pool) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Get("/health/db", func(w http.ResponseWriter, r *http.Request) {
		if pool == nil {
			http.Error(w, "пул подключений к БД не настроен", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), pingTimeout)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "Postgres недоступен: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Handle("/metrics", promhttp.Handler())

	return r
}
