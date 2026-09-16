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
	// Auth — проверка токенов. Без неё закрытые маршруты НЕ подключаются
	// вовсе: отдать их открытыми было бы хуже, чем не отдать совсем.
	Auth *AuthHandler
}

// NewRouter собирает роутер. pool может быть nil в тестах, которые не трогают БД.
func NewRouter(pool *pgxpool.Pool, opts ...Options) http.Handler {
	r := chi.NewRouter()
	// Свой request_id, а не middleware.RequestID из chi: формат должен
	// совпадать с python-версией (hex uuid4), потому что nginx раздаёт часть
	// путей одной версии, часть — другой, и след запроса ищется по одному
	// идентификатору в обоих логах.
	r.Use(withRequestID)
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
		if opt.Auth != nil {
			MountAuth(r, opt.Auth)
		}
		if opt.Reports != nil {
			if opt.Auth == nil {
				// Молча отдать отчёты без проверки токена нельзя: в них
				// лежат пути внутри пакета и куски исходников.
				defaultLogger.Print(
					"маршруты отчётов НЕ подключены: не настроена проверка токенов (OIDC_ISSUER)")
				continue
			}
			MountReports(r, opt.Reports, opt.Auth.Auth)
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
// Доступ — как к самой заявке: достаточно аутентификации, отдельной роли не
// требуется (в python-версии чтение заявки закрыто get_current_user без
// require_roles). Открытыми эти маршруты быть не могут: в отчёте видны пути
// внутри пакета и фрагменты исходного кода.
func MountReports(r chi.Router, h *ReportsHandler, a *Auth) {
	r.Route("/api/v1/request-items/{itemID}/reports", func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/", h.List)
		sub.Get("/{file}", h.Download)
	})
}
