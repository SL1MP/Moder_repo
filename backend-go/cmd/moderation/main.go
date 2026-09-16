// Точка входа сервиса модерации пакетов (Go-версия).
//
// Режим на сейчас — только "api" (HTTP-сервер). Режим "worker" появится вместе
// с очередью на NATS/Valkey (docs/migration-to-go.md, фаза 6); тогда же — решить
// открытый вопрос "один бинарник --mode=api|worker|all (как sentrix) или три
// отдельных" и обновить этот файл.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"moderation/internal/api"
	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Подкоманды. Без аргументов — HTTP-сервер (поведение по умолчанию не
	// меняется: так сервис запускается из docker-compose).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "scan":
			os.Exit(runScan(os.Args[2:], logger))
		case "serve":
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "-h", "--help", "help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n", os.Args[1])
			usage()
			os.Exit(2)
		}
	}

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

	// Хранилище отчётов необязательно: без него сервис поднимается и отвечает
	// health, просто маршруты отчётов не подключаются. Падать на старте из-за
	// отчётов нельзя — иначе недоступный MinIO роняет весь сервис.
	options := api.Options{}
	if cfg.S3Endpoint != "" {
		store, err := storage.NewS3(storage.S3Config{
			Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
			AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, Region: cfg.S3Region,
		})
		if err != nil {
			logger.Error("хранилище отчётов не настроено, выдача отчётов отключена", "error", err)
		} else {
			options.Reports = &api.ReportsHandler{Repo: repo.New(pool), Storage: store}
			logger.Info("хранилище отчётов подключено", "endpoint", cfg.S3Endpoint, "bucket", cfg.S3Bucket)
		}
	} else {
		logger.Warn("S3_ENDPOINT не задан — выдача отчётов о сканировании отключена")
	}

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: api.NewRouter(pool, options),
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

func usage() {
	fmt.Fprint(os.Stderr, `Сервис модерации пакетов (Go-версия).

Использование:
  moderation [serve]          HTTP-сервер: health, метрики, выдача отчётов
  moderation scan --item N    прогнать сканеры содержимого по пакету заявки N
                              и записать отчёты

Конфигурация — через переменные окружения, см. backend-go/README.md.
Обязательна DATABASE_URL; для отчётов нужны также S3_*.
`)
}
