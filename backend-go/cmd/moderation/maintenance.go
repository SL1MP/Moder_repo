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

	"moderation/internal/artifactstore"
	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/maintenance"
	"moderation/internal/osv"
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
	// osvSyncTimeout — снапшот базы уязвимостей это десятки мегабайт и
	// десятки тысяч файлов: ему нужен свой, более щедрый потолок.
	osvSyncTimeout = 30 * time.Minute
)

// maintenanceRunner — периодический запуск регламентных задач.
type maintenanceRunner struct {
	service *maintenance.Service
	logger  *slog.Logger

	quarantineInterval time.Duration
	cleanupInterval    time.Duration
	osvInterval        time.Duration
	orphanTTL          time.Duration
	osv                maintenance.OSVConfig
	vulnMaxScore       float64
}

func newMaintenanceRunner(cfg *config.Config, r *repo.Repo, q *queue.Queue, store storage.Store, logger *slog.Logger) *maintenanceRunner {
	// Артефактори нужно только для снапшота OSV. Его недоступность не должна
	// мешать остальным задачам, поэтому ошибка сборки клиента — не отказ, а
	// выключенная синхронизация.
	artifacts, err := artifactstore.New(artifactstore.Config{
		Kind: cfg.ArtifactStore, BaseURL: cfg.ArtifactBaseURL,
		AuthType: artifactstore.AuthType(cfg.ArtifactAuthType),
		Token:    cfg.ArtifactToken, Username: cfg.ArtifactUser, Password: cfg.ArtifactToken,
	})
	if err != nil {
		logger.Warn("снапшот OSV синхронизироваться не будет: артефактори не настроено", "error", err)
		artifacts = nil
	}
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
			Storage:   store,
			Artifacts: artifacts,
			Logger:    logger,
		},
		logger:             logger,
		quarantineInterval: clampInterval(cfg.QuarantineSweepInterval),
		cleanupInterval:    clampInterval(cfg.S3CleanupInterval),
		osvInterval:        cfg.OSVSyncInterval,
		orphanTTL:          cfg.S3OrphanTTL,
		osv: maintenance.OSVConfig{
			Repo: cfg.ArtifactRepoOSV, Path: cfg.OSVSnapshotPath, LocalPath: cfg.OSVLocalDBPath,
		},
		vulnMaxScore: cfg.VulnMaxScore,
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
	m.syncOSV(ctx, false)

	quarantine := time.NewTicker(m.quarantineInterval)
	defer quarantine.Stop()
	cleanup := time.NewTicker(m.cleanupInterval)
	defer cleanup.Stop()
	// Синхронизацию снапшота можно выключить нулевым интервалом: снапшот
	// кладут и снаружи (scripts/osv_local_snapshot.py, свой конвейер выгрузки).
	var osvTick <-chan time.Time
	if m.osvInterval > 0 {
		osv := time.NewTicker(clampInterval(m.osvInterval))
		defer osv.Stop()
		osvTick = osv.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-quarantine.C:
			m.sweepQuarantine(ctx)
		case <-cleanup.C:
			m.cleanupStorage(ctx)
		case <-osvTick:
			m.syncOSV(ctx, false)
		}
	}
}

// syncOSV загружает снапшот базы уязвимостей, если появился новый.
func (m *maintenanceRunner) syncOSV(ctx context.Context, force bool) {
	if m.service.Artifacts == nil || m.osvInterval <= 0 {
		return
	}
	runCtx, cancel := context.WithTimeout(ctx, osvSyncTimeout)
	defer cancel()
	result, err := m.service.SyncOSVSnapshot(runCtx, m.osv, force)
	if err != nil {
		// Молчать нельзя: пока снапшот не обновляется, каждый пакет уходит к
		// DevSecOps вручную, и снаружи это выглядит как «сервис стал строже».
		m.logger.Error("снапшот OSV не синхронизирован", "error", err)
		return
	}
	if !result.Updated {
		return
	}
	// Новая база — повод пересмотреть уже одобренное: пакет, одобренный вчера,
	// сегодня может оказаться уязвимым, и узнать об этом должен сервис.
	m.rescan(ctx, result.IndexVersionID)
}

// rescan перепроверяет одобренные пакеты по текущей базе уязвимостей.
func (m *maintenanceRunner) rescan(ctx context.Context, indexVersionID *int64) {
	runCtx, cancel := context.WithTimeout(ctx, osvSyncTimeout)
	defer cancel()
	index := osv.NewSnapshotIndex(m.osv.LocalPath)
	if _, err := m.service.RescanApproved(runCtx, index, m.vulnMaxScore, indexVersionID); err != nil {
		m.logger.Error("перепроверка одобренных пакетов не выполнена", "error", err)
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
	osvOnly := fs.Bool("osv-sync", false, "только загрузить снапшот базы уязвимостей")
	rescanOnly := fs.Bool("rescan", false, "только перепроверить одобренные пакеты по текущей базе")
	force := fs.Bool("force", false, "перезагрузить снапшот, даже если версия та же")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Без флагов выполняются все задачи.
	only := *quarantineOnly || *cleanupOnly || *osvOnly || *rescanOnly
	doQuarantine := *quarantineOnly || !only
	doCleanup := *cleanupOnly || !only
	doOSV := *osvOnly || !only
	// Перепроверка по расписанию идёт следом за загрузкой снапшота, поэтому
	// без флагов отдельно её не запускаем — иначе команда каждый раз обходила
	// бы все одобренные пакеты впустую.
	doRescan := *rescanOnly

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
	if doOSV {
		if runner.service.Artifacts == nil {
			fmt.Fprintln(os.Stderr, "артефактори не настроено — снапшот OSV загружать неоткуда")
			code = 1
		} else {
			result, err := runner.service.SyncOSVSnapshot(ctx, runner.osv, *force)
			switch {
			case err != nil:
				logger.Error("снапшот OSV не синхронизирован", "error", err)
				code = 1
			case result.Updated:
				fmt.Printf("Снапшот OSV загружен: версия %s, записей %d\n",
					result.Version, result.Records)
			default:
				fmt.Printf("Снапшот OSV актуален: версия %s\n", result.Version)
			}
		}
	}
	if doQuarantine {
		released, err := runner.service.ReleaseExpiredQuarantine(ctx)
		if err != nil {
			logger.Error("снятие истёкшего карантина не выполнено", "error", err)
			code = 1
		} else {
			fmt.Printf("Карантин снят с пакетов: %d\n", released)
		}
	}
	if doRescan {
		result, err := runner.service.RescanApproved(ctx,
			osv.NewSnapshotIndex(cfg.OSVLocalDBPath), cfg.VulnMaxScore, nil)
		if err != nil {
			logger.Error("перепроверка одобренных пакетов не выполнена", "error", err)
			code = 1
		} else {
			fmt.Printf("Перепроверено пакетов: %d, отозвано: %d\n", result.Checked, result.Revoked)
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
