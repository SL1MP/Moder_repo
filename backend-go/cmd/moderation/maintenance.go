package main

import (
	"context"
	"errors"
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
	"moderation/internal/osv"
	"moderation/internal/queue"
	"moderation/internal/repo"
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
	catalog            maintenance.CatalogConfig
}

func newMaintenanceRunner(cfg *config.Config, r *repo.Repo, q *queue.Queue, st *stores, logger *slog.Logger) *maintenanceRunner {
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
			Storage:   st.Staging,
			Artifacts: st.Artifacts,
			Logger:    logger,
		},
		logger:             logger,
		quarantineInterval: clampInterval(cfg.QuarantineSweepInterval),
		cleanupInterval:    clampInterval(cfg.StagingCleanupInterval),
		osvInterval:        cfg.OSVSyncInterval,
		orphanTTL:          cfg.StagingOrphanTTL,
		osv:                osvConfig(cfg),
		vulnMaxScore:       cfg.VulnMaxScore,
		catalog: maintenance.CatalogConfig{
			Managers: cfg.ArtifactCatalogSyncManagers,
			Repositories: cfg.ArtifactRepos,
			Registry: newRegistry(cfg, nil),
		},
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

	// Каталог не должен ждать первоначальную загрузку и распаковку OSV, а
	// также последующую перепроверку всех одобренных версий. Эти операции
	// могут занимать десятки минут, тогда как очередь каталога опрашивается
	// независимо и должна начать разбираться сразу после запуска worker.
	// Цикл нужен и при пустом списке по умолчанию: администратор может выбрать
	// менеджеры непосредственно при ручном запуске в web. Сам цикл ничего не
	// синхронизирует без записи queued в Postgres, поэтому его запуск не
	// превращает синхронизацию в автоматическую.
	go m.catalogLoop(ctx)

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

// catalogLoop отделён от карантина и уборки: полный импорт большой
// корпоративной базы может идти десятки минут и не должен задерживать другие
// регламентные задачи. Сам worker ничего не ставит в очередь: запуск создаётся
// только явным действием администратора в web/API либо командой maintenance
// --catalog-sync. После перезапуска worker продолжает лишь уже поставленную
// вручную задачу.
func (m *maintenanceRunner) catalogLoop(ctx context.Context) {
	if recovered, err := m.service.Repo.RecoverCatalogSyncRuns(
		ctx, time.Now().UTC().Add(-maintenance.CatalogSyncTimeout)); err != nil {
		m.logger.Error("зависший запуск синхронизации каталога не проверен", "error", err)
	} else if recovered > 0 {
		m.logger.Warn("зависший запуск синхронизации каталога закрыт", "запусков", recovered)
	}
	poll := time.NewTicker(10 * time.Second)
	defer poll.Stop()
	// Не ждём первого poll: если администратор поставил задачу до запуска
	// worker, её можно забрать сразу. Новая задача при этом не создаётся.
	m.processCatalogRun(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			m.processCatalogRun(ctx)
		}
	}
}

func (m *maintenanceRunner) processCatalogRun(ctx context.Context) {
	if recovered, err := m.service.Repo.RecoverCatalogSyncRuns(
		ctx, time.Now().UTC().Add(-maintenance.CatalogSyncTimeout)); err != nil {
		m.logger.Warn("зависший запуск синхронизации каталога не проверен", "error", err)
	} else if recovered > 0 {
		m.logger.Warn("зависший запуск синхронизации каталога закрыт; повторите его вручную",
			"запусков", recovered)
	}
	run, err := m.service.Repo.ClaimCatalogSync(ctx)
	if err != nil {
		m.logger.Error("запуск синхронизации каталога не получен", "error", err)
		return
	}
	if run == nil {
		return
	}
	runCtx, cancel := context.WithTimeout(ctx, maintenance.CatalogSyncTimeout)
	catalogCfg := m.catalog
	catalogCfg.Managers = run.Managers
	result, syncErr := m.service.SyncTrustedCatalog(runCtx, catalogCfg, run)
	cancel()
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer finishCancel()
	if err := m.service.Repo.FinishCatalogSync(finishCtx, run.ID, result, syncErr); err != nil {
		m.logger.Error("результат синхронизации каталога не сохранён", "run", run.ID, "error", err)
		return
	}
	if syncErr != nil {
		m.logger.Error("каталог внутреннего артефактори не синхронизирован", "run", run.ID, "error", syncErr)
		return
	}
	m.logger.Info("каталог внутреннего артефактори синхронизирован",
		"run", run.ID, "найдено", result.Discovered, "добавлено", result.Imported,
		"обновлено", result.Updated, "пропущено", result.Skipped, "ошибок", result.Errors)
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
		if errors.Is(err, osv.ErrSnapshotSyncInProgress) {
			m.logger.Info("синхронизация OSV пропущена: её уже выполняет другой worker")
			return
		}
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
	catalogOnly := fs.Bool("catalog-sync", false, "только синхронизировать web-базу с доверенными репозиториями")
	force := fs.Bool("force", false, "перезагрузить снапшот, даже если версия та же")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Без флагов выполняются все задачи.
	only := *quarantineOnly || *cleanupOnly || *osvOnly || *rescanOnly || *catalogOnly
	doQuarantine := *quarantineOnly || !only
	doCleanup := *cleanupOnly || !only
	doOSV := *osvOnly || !only
	// Перепроверка по расписанию идёт следом за загрузкой снапшота, поэтому
	// без флагов отдельно её не запускаем — иначе команда каждый раз обходила
	// бы все одобренные пакеты впустую.
	doRescan := *rescanOnly
	doCatalog := *catalogOnly

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("конфигурация невалидна", "error", err)
		return 1
	}
	if err := installCorporateCAs(cfg, logger); err != nil {
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
	applyStoredSettings(ctx, pool, cfg, logger)

	r := repo.New(pool)
	q := queue.New(pool, staleAfter(cfg))
	st, err := newStores(cfg, newArtifactHTTPClient())
	if err != nil {
		if doCleanup {
			// Молча пропустить уборку значило бы отчитаться об успехе, ничего
			// не сделав: хранилище не настроено, а файлы в нём — есть.
			fmt.Fprintf(os.Stderr, "промежуточная зона недоступна (%v) — уборка пропущена\n", err)
			doCleanup = false
		}
		logger.Error("хранилище", "error", err)
		return 1
	}

	runner := newMaintenanceRunner(cfg, r, q, st, logger)
	code := 0
	if doCatalog {
		run, err := r.EnqueueCatalogSync(ctx, "cli", cfg.ArtifactCatalogSyncManagers, nil)
		if err != nil {
			logger.Error("синхронизация каталога не поставлена в очередь", "error", err)
			code = 1
		} else {
			fmt.Printf("Синхронизация каталога поставлена в очередь: запуск #%d, статус %s\n", run.ID, run.Status)
		}
	}
	if doOSV {
		if runner.service.Artifacts == nil {
			fmt.Fprintln(os.Stderr, "артефактори не настроено — снапшот OSV загружать неоткуда")
			code = 1
		} else {
			syncCtx, cancel := context.WithTimeout(ctx, osvSyncTimeout)
			result, err := runner.service.SyncOSVSnapshot(syncCtx, runner.osv, *force)
			cancel()
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
		removed, err := runner.service.CleanupOrphanObjects(ctx, cfg.StagingOrphanTTL)
		if err != nil {
			logger.Error("уборка временного хранилища не выполнена", "error", err)
			code = 1
		} else {
			fmt.Printf("Удалено объектов из временного хранилища: %d\n", removed)
		}
	}
	return code
}
