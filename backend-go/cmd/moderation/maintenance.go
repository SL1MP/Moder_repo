package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/maintenance"
	"moderation/internal/queue"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

// Регламентные задачи рядом с воркером.
//
// Почему внутри воркера, а не отдельным процессом-планировщиком (как beat в
// python-версии): задачи короткие, редкие и работают с той же базой и тем же
// хранилищем. Отдельный контейнер добавил бы в развёртывание ещё одну
// сущность, которую надо не забыть поднять, — а забытый планировщик ничем не
// отличается от отсутствующего: карантин просто перестанет сниматься, и
// никто не заметит.
//
// Если воркеров несколько, задачи выполнятся в каждом. Это допустимо: снятие
// карантина идёт по статусу (второй заход не найдёт уже снятые), уборка
// хранилища — по признаку «не удалён» (повторное удаление ключа безвредно).

const (
	// minMaintenanceInterval — чаще этого гонять задачи бессмысленно: они
	// ходят в базу по всем заявкам и по всем зависшим объектам.
	minMaintenanceInterval = time.Minute
	// maintenanceTimeout — потолок на один прогон задачи.
	maintenanceTimeout = 10 * time.Minute
)

// maintenanceRunner — периодический запуск регламентных задач.
type maintenanceRunner struct {
	service *maintenance.Service
	logger  *slog.Logger

	quarantineInterval time.Duration
	cleanupInterval    time.Duration
	orphanTTL          time.Duration
}

func newMaintenanceRunner(cfg *config.Config, r *repo.Repo, q *queue.Queue, store storage.Store, logger *slog.Logger) *maintenanceRunner {
	return &maintenanceRunner{
		service: &maintenance.Service{
			Repo: r,
			// Тот же сервис решений, что и у кнопки DevSecOps: снятие
			// карантина обязано вести себя одинаково, кем бы оно ни было
			// вызвано.
			Decisions: &decisions.Service{
				Repo: r,
				Resume: func(ctx context.Context, item *domain.RequestItem, fromStep string) error {
					return q.Enqueue(ctx, item.ID, fromStep)
				},
			},
			Storage: store,
			Logger:  logger,
		},
		logger:             logger,
		quarantineInterval: clampInterval(cfg.QuarantineSweepInterval),
		cleanupInterval:    clampInterval(cfg.S3CleanupInterval),
		orphanTTL:          cfg.S3OrphanTTL,
	}
}

func clampInterval(d time.Duration) time.Duration {
	if d < minMaintenanceInterval {
		return minMaintenanceInterval
	}
	return d
}

// run гоняет задачи до отмены контекста. Первый прогон — сразу при старте:
// сервис мог простоять выключенным дольше интервала, и ждать ещё четверть
// часа, чтобы снять карантин, истёкший вчера, незачем.
func (m *maintenanceRunner) run(ctx context.Context) {
	m.logger.Info("регламентные задачи запущены",
		"карантин", m.quarantineInterval, "уборка хранилища", m.cleanupInterval,
		"срок жизни объекта", m.orphanTTL)

	m.sweepQuarantine(ctx)
	m.cleanupStorage(ctx)

	quarantine := time.NewTicker(m.quarantineInterval)
	defer quarantine.Stop()
	cleanup := time.NewTicker(m.cleanupInterval)
	defer cleanup.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-quarantine.C:
			m.sweepQuarantine(ctx)
		case <-cleanup.C:
			m.cleanupStorage(ctx)
		}
	}
}

func (m *maintenanceRunner) sweepQuarantine(ctx context.Context) {
	runCtx, cancel := context.WithTimeout(ctx, maintenanceTimeout)
	defer cancel()
	if _, err := m.service.ReleaseExpiredQuarantine(runCtx); err != nil {
		m.logger.Error("снятие истёкшего карантина не выполнено", "error", err)
	}
}

func (m *maintenanceRunner) cleanupStorage(ctx context.Context) {
	runCtx, cancel := context.WithTimeout(ctx, maintenanceTimeout)
	defer cancel()
	if _, err := m.service.CleanupOrphanObjects(runCtx, m.orphanTTL); err != nil {
		m.logger.Error("уборка временного хранилища не выполнена", "error", err)
	}
}

// runMaintenance — разовый прогон регламентных задач.
//
// Нужен там же, где и остальные подкоманды: на стенде, где что-то уже пошло не
// так. Пакеты застряли в карантине, потому что воркер был выключен, — эта
// команда снимает их сейчас, а не через пятнадцать минут после починки.
func runMaintenance(args []string, logger *slog.Logger) int {
	fs := flag.NewFlagSet("maintenance", flag.ContinueOnError)
	quarantineOnly := fs.Bool("quarantine", false, "только снять истёкший карантин")
	cleanupOnly := fs.Bool("cleanup", false, "только убрать временное хранилище")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Без флагов выполняются обе задачи.
	doQuarantine := *quarantineOnly || !*cleanupOnly
	doCleanup := *cleanupOnly || !*quarantineOnly

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("конфигурация невалидна", "error", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("не удалось подключиться к Postgres", "error", err)
		return 1
	}
	defer pool.Close()

	r := repo.New(pool)
	q := queue.New(pool, staleAfter(cfg))
	var store storage.Store
	if cfg.S3Endpoint != "" {
		store, err = storage.NewS3(storage.S3Config{
			Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
			AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, Region: cfg.S3Region,
			VirtualHost: cfg.S3VirtualHost,
		})
		if err != nil {
			logger.Error("хранилище", "error", err)
			return 1
		}
	} else if doCleanup {
		// Молча пропустить уборку значило бы отчитаться об успехе, ничего не
		// сделав: хранилище не настроено, а объекты в нём — есть.
		fmt.Fprintln(os.Stderr, "S3_ENDPOINT не задан — убирать нечего; уборка пропущена")
		doCleanup = false
	}

	runner := newMaintenanceRunner(cfg, r, q, store, logger)
	code := 0
	if doQuarantine {
		released, err := runner.service.ReleaseExpiredQuarantine(ctx)
		if err != nil {
			logger.Error("снятие истёкшего карантина не выполнено", "error", err)
			code = 1
		} else {
			fmt.Printf("Карантин снят с пакетов: %d\n", released)
		}
	}
	if doCleanup {
		removed, err := runner.service.CleanupOrphanObjects(ctx, cfg.S3OrphanTTL)
		if err != nil {
			logger.Error("уборка временного хранилища не выполнена", "error", err)
			code = 1
		} else {
			fmt.Printf("Удалено объектов из временного хранилища: %d\n", removed)
		}
	}
	return code
}
