// Package api собирает chi-роутер сервиса. Начинается с health/metrics —
// остальные маршруты (см. docs/api.md) переносятся по мере переноса пайплайна
// и адаптеров, см. docs/migration-to-go.md, "Фазы".
package api

import (
	"log"
	"os"

	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const pingTimeout = 3 * time.Second

// Options — что подключать в роутер помимо health и metrics. Nil-поля просто
// не подключаются: сервис должен подниматься и без хранилища отчётов, отдавая
// health, а не падать на старте.
type Options struct {
	Reports *ReportsHandler
}

// NewRouter собирает роутер. pool может быть nil в тестах, которые не трогают БД.
func NewRouter(pool *pgxpool.Pool, opts ...Options) http.Handler {
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

	for _, opt := range opts {
		if opt.Reports != nil {
			MountReports(r, opt.Reports)
		}
	}

	return r
}

// defaultLogger — временный логгер API. Заменяется структурным логгером при
// переносе логирования; json_ensure_ascii-эквивалент (не экранировать
// кириллицу) там обязателен — см. handoff, п. 8.4.
var defaultLogger = log.New(os.Stderr, "[api] ", log.LstdFlags)

// MountReports подключает маршруты отчётов о сканировании.
//
// Пути под /api/v1/request-items/{itemID}/..., а не под /requests/{id}/...:
// отчёт относится к конкретному пакету заявки, а не к заявке целиком, и в
// заявке таких пакетов десятки.
func MountReports(r chi.Router, h *ReportsHandler) {
	r.Route("/api/v1/request-items/{itemID}/reports", func(sub chi.Router) {
		sub.Get("/", h.List)
		sub.Get("/{file}", h.Download)
	})
}
