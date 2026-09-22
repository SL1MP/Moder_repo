package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/pipeline"
	"moderation/internal/queue"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

// Команда `moderation worker` — прогон конвейера по пакетам из очереди.
//
// Очередь — строки request_item в статусе `queued` (см. internal/queue).
// Воркер ждёт уведомления, забирает пакет атомарно, гоняет по нему все девять
// шагов и снимает с обработки. Пока прогон идёт, воркер отмечается в той же
// строке: по этой отметке упавший процесс отличается от работающего.
//
// Go-воркер и python-воркер могут работать одновременно: захват у них общий
// (UPDATE ... WHERE status = 'queued'), и пакет достанется ровно одному.
// Это и позволяет переносить обработку постепенно, а не в один день.

const (
	// defaultWorkerConcurrency — сколько пакетов обрабатывается разом. Прогон
	// упирается в сеть (реестр, хранилище) и в сканеры, а не в процессор,
	// поэтому по умолчанию их несколько.
	defaultWorkerConcurrency = 2
	// defaultMaxAttempts — сколько раз повторять упавший прогон.
	defaultMaxAttempts = 3
	// heartbeatInterval — как часто прогон отмечается живым. Должен быть
	// заметно меньше StaleAfter, иначе живой прогон успеют перехватить.
	heartbeatInterval = 30 * time.Second
	// idleWait — сколько ждать уведомления, прежде чем заглянуть в очередь
	// самому. Подстраховка на случай потерянного NOTIFY.
	idleWait = 30 * time.Second
	// defaultRetryPause — пауза перед повтором упавшего прогона.
	defaultRetryPause = 10 * time.Second
	// itemTimeout — потолок на один пакет: скачивание, распаковка и два
	// сканера. Больше — почти наверняка зависший внешний вызов.
	itemTimeout = 30 * time.Minute
)

func runWorker(args []string, logger *slog.Logger) int {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	concurrency := fs.Int("concurrency", defaultWorkerConcurrency, "сколько пакетов обрабатывать разом")
	once := fs.Bool("once", false, "разобрать очередь и выйти (для CI и ручной прогонки)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *concurrency <= 0 {
		fmt.Fprintln(os.Stderr, "--concurrency должен быть положительным")
		return 2
	}

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

	w, err := newPipelineWorker(cfg, pool, logger)
	if err != nil {
		logger.Error("воркер не собран", "error", err)
		return 1
	}

	if *once {
		// В разовом прогоне ждать между попытками незачем: команду зовут
		// руками или из CI, и там важнее увидеть исход, чем дать сети
		// отдышаться.
		w.retryPause = 0
		n := w.drain(ctx)
		logger.Info("очередь разобрана", "обработано", n)
		return 0
	}

	queued, running, err := w.queue.Depth(ctx)
	if err != nil {
		logger.Warn("глубину очереди прочитать не удалось", "error", err)
	}
	logger.Info("воркер запущен", "потоков", *concurrency,
		"в очереди", queued, "в работе", running)

	// Регламентные задачи: снятие истёкшего карантина и уборка временного
	// хранилища. Выключаются флагом — в разовом прогоне и в CI они не нужны.
	if cfg.MaintenanceEnabled {
		go newMaintenanceRunner(cfg, w.repo, w.queue, w.storage, logger).run(ctx)
	} else {
		logger.Warn("регламентные задачи выключены (MAINTENANCE_ENABLED=false) — " +
			"карантин сам не снимется, временное хранилище не убирается")
	}

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			w.loop(ctx, n)
		}(i)
	}
	wg.Wait()
	logger.Info("воркер остановлен")
	return 0
}

// pipelineWorker — зависимости обработки.
type pipelineWorker struct {
	// retryPause — пауза перед возвратом упавшего пакета в очередь. Поле, а не
	// константа: в режиме --once ждать незачем.
	retryPause time.Duration

	cfg     *config.Config
	repo    *repo.Repo
	queue   *queue.Queue
	storage storage.Store
	logger  *slog.Logger
}

func newPipelineWorker(cfg *config.Config, pool *pgxpool.Pool, logger *slog.Logger) (*pipelineWorker, error) {
	// Хранилище обязательно: без него шаг скачивания некуда класть артефакт, и
	// каждый пакет упал бы на нём. Здесь это повод не стартовать, в отличие от
	// HTTP-сервиса, который и без хранилища обязан отвечать health.
	if cfg.S3Endpoint == "" {
		return nil, errors.New("S3_ENDPOINT не задан — конвейеру некуда класть артефакты")
	}
	store, err := storage.NewS3(storage.S3Config{
		Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, Region: cfg.S3Region,
		VirtualHost: cfg.S3VirtualHost,
	})
	if err != nil {
		return nil, fmt.Errorf("хранилище: %w", err)
	}
	return &pipelineWorker{
		cfg: cfg, repo: repo.New(pool), storage: store, logger: logger,
		queue: queue.New(pool, staleAfter(cfg)), retryPause: defaultRetryPause,
	}, nil
}

// staleAfter — через сколько молчания прогон считается брошенным. Порог тот
// же, что у python-версии: PIPELINE_STUCK_AFTER_SECONDS × 3.
func staleAfter(cfg *config.Config) time.Duration {
	return cfg.PipelineStuckAfter * 3
}

// loop — один поток обработки: ждать, забирать, обрабатывать, пока не попросят
// остановиться.
func (w *pipelineWorker) loop(ctx context.Context, n int) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, err := w.queue.Claim(ctx)
		switch {
		case errors.Is(err, queue.ErrEmpty):
			// Очередь пуста — ждём уведомления. Таймаут ожидания заодно
			// служит опросом: потерянный NOTIFY не должен означать пакет,
			// который лежит до перезапуска сервиса.
			if err := w.queue.Wait(ctx, idleWait); err != nil && ctx.Err() == nil {
				w.logger.Warn("ожидание задач прервано", "поток", n, "error", err)
				time.Sleep(time.Second)
			}
			continue
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			w.logger.Error("не удалось забрать пакет из очереди", "поток", n, "error", err)
			time.Sleep(2 * time.Second)
			continue
		}
		w.handle(ctx, job)
	}
}

// drain разбирает очередь до конца и возвращает число обработанных пакетов.
// Режим `--once`: удобен в CI и когда очередь надо разобрать руками.
func (w *pipelineWorker) drain(ctx context.Context) int {
	processed := 0
	for {
		job, err := w.queue.Claim(ctx)
		if errors.Is(err, queue.ErrEmpty) {
			return processed
		}
		if err != nil {
			w.logger.Error("не удалось забрать пакет из очереди", "error", err)
			return processed
		}
		w.handle(ctx, job)
		processed++
	}
}

// handle обрабатывает один пакет целиком, включая исход.
func (w *pipelineWorker) handle(ctx context.Context, job queue.Job) {
	runCtx, cancel := context.WithTimeout(ctx, itemTimeout)
	defer cancel()

	// Отметка о жизни: пока она обновляется, пакет не перехватят. Если строку
	// всё-таки отобрали (её статус сменили из API), прогон прекращается —
	// дописывать шаги поверх чужой работы нельзя.
	stopBeat := w.beat(runCtx, cancel, job.ItemID)
	defer stopBeat()

	started := time.Now()
	// Статус заявки — свёртка статусов её пакетов. Пересчёт стоит в defer, а
	// не сразу после прогона: при неудаче статус пакета ставится ниже по
	// коду (повтор или окончательный отказ), и пересчёт до этого зафиксировал
	// бы промежуточное состояние. Без пересчёта заявка навсегда остаётся «в
	// обработке», хотя её пакеты давно разошлись по очередям ролей.
	defer w.recompute(ctx, job.ItemID)

	result, err := w.runPipeline(runCtx, job)
	if err == nil {
		w.deliver(ctx, job.ItemID, result.Notifications)
		if err := w.queue.Done(ctx, job.ItemID); err != nil {
			w.logger.Error("пакет не снят с обработки", "item", job.ItemID, "error", err)
		}
		w.logger.Info("пакет обработан", "item", job.ItemID,
			"статус", result.ItemStatus, "последний шаг", result.LastStep,
			"за", time.Since(started).Round(time.Millisecond).String())
		return
	}

	// Контекст отменён остановкой сервиса — это не неудача пакета. Оставляем
	// его в `running`: отметка о жизни перестанет обновляться, и следующий
	// воркер подберёт его как брошенный.
	if ctx.Err() != nil {
		w.logger.Info("прогон прерван остановкой сервиса", "item", job.ItemID)
		return
	}

	// Пауза перед повтором. Без неё три попытки сгорают за миллисекунды:
	// упавший прогон возвращается в очередь, тут же будит воркера и падает
	// снова — а сбои здесь внешние и временные, и повтор без паузы не даёт
	// внешнему сбою пройти. Ждём в этом же потоке: воркеров несколько, попыток
	// не больше трёх, и отдельный планировщик отложенных задач ради этого —
	// сложность, которая себя не окупает.
	if w.retryPause > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.retryPause):
		}
	}

	retried, retryErr := w.queue.Retry(ctx, job.ItemID, defaultMaxAttempts)
	if errors.Is(retryErr, queue.ErrNotOurs) {
		// Пакет ушёл из-под прогона, пока он шёл: чаще всего автор закрыл
		// заявку. Возвращать его в очередь или помечать неудачей нельзя — это
		// отменило бы отмену.
		w.logger.Info("прогон не удался, но пакет уже не наш — оставляю как есть",
			"item", job.ItemID, "error", err)
		return
	}
	if retryErr != nil {
		w.logger.Error("повтор не назначен", "item", job.ItemID, "error", retryErr)
		return
	}
	if retried {
		w.logger.Warn("прогон не удался, пакет вернулся в очередь",
			"item", job.ItemID, "error", err)
		return
	}
	reason := fmt.Sprintf("Проверка не выполнена после %d попыток: %v", defaultMaxAttempts, err)
	failErr := w.queue.Fail(ctx, job.ItemID, reason,
		"Техническая ошибка проверки. Перезапустите заявку или обратитесь к администратору.")
	switch {
	case errors.Is(failErr, queue.ErrNotOurs):
		w.logger.Info("пакет уже не наш — неудачей не помечаю", "item", job.ItemID)
		return
	case failErr != nil:
		w.logger.Error("пакет не помечен неудачей", "item", job.ItemID, "error", failErr)
	}
	w.logger.Error("прогон не удался окончательно", "item", job.ItemID, "error", err)
}

// beat держит отметку о жизни прогона. Возвращает функцию остановки.
func (w *pipelineWorker) beat(ctx context.Context, cancel context.CancelFunc, itemID int64) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				alive, err := w.queue.Heartbeat(ctx, itemID)
				if err != nil {
					w.logger.Warn("отметка о жизни не прошла", "item", itemID, "error", err)
					continue
				}
				if !alive {
					// Пакет больше не наш: его статус сменили снаружи или
					// строку перехватил другой воркер. Прогон прекращаем.
					w.logger.Warn("пакет больше не принадлежит этому прогону, останавливаюсь",
						"item", itemID)
					cancel()
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// runPipeline собирает контекст и прогоняет конвейер.
func (w *pipelineWorker) runPipeline(ctx context.Context, job queue.Job) (pipeline.Result, error) {
	pc, err := buildScanContext(ctx, w.repo, w.storage, w.cfg)
	if err != nil {
		return pipeline.Result{}, err
	}
	if err := loadItem(ctx, w.repo, pc, job.ItemID); err != nil {
		return pipeline.Result{}, err
	}
	return pipeline.Run(ctx, pc, job.FromStep)
}

// eventTitles — заголовки уведомлений, те же, что у python-версии
// (adapters/notifier.py EVENT_TITLES): одно и то же событие не должно
// называться по-разному в зависимости от того, какая версия его создала.
var eventTitles = map[string]string{
	"request_awaits_security": "Заявка ждёт DevSecOps",
	"request_awaits_legal":    "Заявка ждёт юристов",
	"license_claimed":         "Заявлена лицензия",
	"comment_added":           "Новое сообщение в обсуждении",
	"decision_made":           "Принято решение по пакету",
	"quarantine_released":     "Карантин снят",
	"package_revoked":         "Пакет отозван",
	"package_approved":        "Пакет одобрен",
	"pipeline_failed":         "Ошибка проверки пакета",
}

// deliver рассылает уведомления, которые конвейер вернул как «кого позвать».
//
// Конвейер их не отправляет сам намеренно: шаг знает, кого звать, но не
// знает, куда — это дело вызывающего. Без этой рассылки пакет вставал бы в
// очередь роли молча, и DevSecOps узнавал бы о нём, только заглянув в
// интерфейс.
func (w *pipelineWorker) deliver(ctx context.Context, item int64, notifications []pipeline.Notification) {
	if len(notifications) == 0 {
		return
	}
	requestItemID := item
	for _, n := range notifications {
		recipients, err := w.repo.UserIDsByRoles(ctx, n.Roles)
		if err != nil {
			w.logger.Error("получатели уведомления не найдены",
				"item", item, "событие", n.Event, "error", err)
			continue
		}
		if len(recipients) == 0 {
			// Ролей нет ни у кого — уведомить некого. Это не сбой доставки, а
			// незаполненный каталог, и молчать о нём нельзя: очередь роли
			// будет наполняться, а смотреть в неё некому.
			w.logger.Warn("уведомлять некого: нет пользователей с ролью",
				"item", item, "роли", n.Roles, "событие", n.Event)
			continue
		}
		title := eventTitles[n.Event]
		if title == "" {
			title = n.Event
		}
		body := n.Message
		notification := domain.Notification{
			Event: n.Event, Title: title, RequestItemID: &requestItemID,
			CreatedAt: time.Now().UTC(),
		}
		if body != "" {
			notification.Body = &body
		}
		if _, err := w.repo.InsertNotifications(ctx, recipients, notification); err != nil {
			// Уведомление — не результат проверки: его потеря не повод
			// объявлять прогон неудачным и повторять всю работу.
			w.logger.Error("уведомления не созданы", "item", item, "событие", n.Event, "error", err)
		}
	}
}

// recompute пересчитывает статус заявки, которой принадлежит пакет.
func (w *pipelineWorker) recompute(ctx context.Context, itemID int64) {
	item, err := w.repo.GetRequestItem(ctx, itemID)
	if err != nil || item == nil {
		if err != nil {
			w.logger.Error("статус заявки не пересчитан: пакет не прочитан",
				"item", itemID, "error", err)
		}
		return
	}
	if _, err := w.repo.RecomputeRequestStatus(ctx, item.RequestID); err != nil {
		w.logger.Error("статус заявки не пересчитан",
			"item", itemID, "request", item.RequestID, "error", err)
	}
}
