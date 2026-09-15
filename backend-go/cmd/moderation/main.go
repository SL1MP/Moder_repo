// Точка входа сервиса модерации пакетов (Go-версия).
//
// Режим на сейчас — только "api" (HTTP-сервер). Режим "worker" появится вместе
// с очередью на NATS/Valkey (docs/migration-to-go.md, фаза 6); тогда же — решить
// открытый вопрос "один бинарник --mode=api|worker|all (как sentrix) или три
// отдельных" и обновить этот файл.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"moderation/internal/api"
	"moderation/internal/config"
	"moderation/internal/db"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("конфигурация невалидна", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("не удалось подключиться к Postgres", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: api.NewRouter(pool),
	}

	go func() {
		logger.Info("сервис запущен", "addr", cfg.ListenAddr, "env", cfg.AppEnv)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP-сервер завершился с ошибкой", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("получен сигнал остановки, завершаю работу")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("ошибка при остановке HTTP-сервера", "error", err)
	}
}
