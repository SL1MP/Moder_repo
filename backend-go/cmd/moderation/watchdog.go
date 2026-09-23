package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"moderation/internal/metrics"
	"moderation/internal/queue"
)

// Сторож очереди в процессе HTTP-сервиса.
//
// Постановка в очередь (internal/queue.Enqueue) — это строка request_item в
// статусе `queued` плюс pg_notify. Разбирать её должен выделенный воркер
// (`moderation worker`). Если воркера нет — не поднят профиль в compose, упал
// процесс, некому слушать — пакет молча остаётся «в очереди», и снаружи это
// выглядит как «проверка идёт вечно». Именно это и случилось после того, как
// создание заявок переехало на Go: маршрут ведёт в Go, а воркер по умолчанию
// выключен.
//
// Поэтому сторож живёт в процессе API (он точно работает, раз пользователь
// видит UI) и раз в PIPELINE_WATCHDOG_INTERVAL_SECONDS забирает пакеты,
// пролежавшие в очереди дольше PIPELINE_STUCK_AFTER_SECONDS, — и гоняет
// конвейер прямо здесь.
//
// Отличие от python-сторожа: тот проверяет, жив ли worker, и либо
// переотправляет задачу, либо выполняет её сам. Здесь проверять некого:
// выделенный воркер забирает пакет сразу (Claim без порога), поэтому до
// сторожа доживает только то, что никто не взял. Ждать minAge — это и есть
// «дать воркеру шанс сделать работу штатно».
//
// Двойного прогона не будет: захват общий (ClaimStale — тот же UPDATE со
// SKIP LOCKED и повторной проверкой статуса), и пакет достанется ровно одному
// процессу.

// minWatchdogInterval — ниже этого порога опрос очереди не опускается. Сторож
// живёт рядом с HTTP-обработчиками и занимает то же соединение к Postgres:
// опрос раз в секунду навредит больше, чем поможет.
const minWatchdogInterval = 5 * time.Second

// staleClaimer — то, что сторож берёт из очереди. Интерфейс, а не *queue.Queue:
// проход проверяется без Postgres, а сам захват — интеграционными тестами
// очереди (internal/queue).
type staleClaimer interface {
	ClaimStale(ctx context.Context, minAge time.Duration) (queue.Job, error)
	// Stuck — сколько пакетов лежит в очереди дольше minAge. Нужен метрикам:
	// сторож забирает по одному, а знать надо, сколько их всего.
	Stuck(ctx context.Context, minAge time.Duration) (int, error)
}

// watchdog — параметры прохода. Отдельный тип, а не замыкание: в тестах проход
// вызывается напрямую, без таймеров.
type watchdog struct {
	claim  staleClaimer
	handle func(ctx context.Context, job queue.Job)

	interval time.Duration
	// minAge — сколько пакет должен пролежать в очереди, прежде чем сторож
	// сочтёт, что выделенный воркер его не возьмёт.
	minAge time.Duration
	logger *slog.Logger
}

// newWatchdog собирает сторожа поверх обычного воркера конвейера: прогон у них
// один и тот же, отличается только то, какие пакеты видит захват.
func newWatchdog(w *pipelineWorker, interval, minAge time.Duration, logger *slog.Logger) *watchdog {
	return &watchdog{
		claim: w.queue, handle: w.handle,
		interval: interval, minAge: minAge, logger: logger,
	}
}

// run — фоновый цикл. Первый проход тоже с задержкой: свежепоставленный пакет
// должен успеть уйти выделенному воркеру.
func (wd *watchdog) run(ctx context.Context) {
	interval := wd.interval
	if interval < minWatchdogInterval {
		interval = minWatchdogInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	wd.logger.Info("сторож очереди запущен",
		"проход раз в", interval.String(), "порог ожидания", wd.minAge.String())

	for {
		select {
		case <-ctx.Done():
			wd.logger.Info("сторож очереди остановлен")
			return
		case <-ticker.C:
			wd.observe(ctx)
			wd.sweep(ctx)
		}
	}
}

// observe обновляет метрики состояния очереди.
//
// Что такое worker_alive здесь: в python-версии это был ответ Celery на ping,
// а у go-воркера своего HTTP нет и пинговать его нечем. Поэтому метрика
// выводится из наблюдаемого следствия: если в очереди лежат пакеты, которых
// никто не забрал дольше порога, значит воркер свою работу не делает — что бы
// ни показывал `docker compose ps`. Обратное тоже верно: пустая очередь
// залежавшихся означает, что забирать успевают.
//
// Определение косвенное, и врать им нельзя: метрика отвечает на вопрос
// «разбирается ли очередь», а не «жив ли процесс».
func (wd *watchdog) observe(ctx context.Context) {
	stuck, err := wd.claim.Stuck(ctx, wd.minAge)
	if err != nil {
		if ctx.Err() == nil {
			wd.logger.Warn("состояние очереди не измерено", "error", err)
		}
		// Прежние значения не трогаем: обнулить их значило бы показать на
		// графике «всё хорошо» ровно тогда, когда мы перестали это знать.
		return
	}
	metrics.StuckItems.Set(float64(stuck))
	if stuck > 0 {
		metrics.WorkerAlive.Set(0)
		return
	}
	metrics.WorkerAlive.Set(1)
}

// sweep — один проход: разобрать всё, что залежалось. Возвращает число
// обработанных пакетов.
//
// Проход не ограничен по числу пакетов: тик следующего прохода пропускается,
// пока идёт этот, поэтому «разобрать до конца» не значит «копить проходы».
// Ограничение по времени на каждый пакет остаётся за handle (itemTimeout).
func (wd *watchdog) sweep(ctx context.Context) int {
	processed := 0
	for {
		if ctx.Err() != nil {
			return processed
		}
		job, err := wd.claim.ClaimStale(ctx, wd.minAge)
		if errors.Is(err, queue.ErrEmpty) {
			return processed
		}
		if err != nil {
			if ctx.Err() == nil {
				wd.logger.Error("сторож не смог забрать пакет", "error", err)
			}
			return processed
		}
		if processed == 0 {
			// Громко: сторож — страховка, и его работа означает, что
			// выделенный воркер свою работу не делает. Молчаливое
			// «всё как-то само обработалось» скрыло бы мёртвого воркера.
			wd.logger.Warn("сторож нашёл залежавшийся пакет — выделенный воркер не забрал его; "+
				"проверьте, работает ли `moderation worker` (docker compose ps worker-go)",
				"item", job.ItemID, "пролежал больше", wd.minAge.String())
		}
		wd.handle(ctx, job)
		processed++
		// Срабатывания сторожа — метрика, по которой видно, что выделенный
		// воркер не справляется. Сторож — страховка, и её работа не должна
		// быть нормой; без счётчика это заметно только по логам, которые
		// никто не читает, пока не сломалось.
		metrics.WatchdogRecoveredTotal.WithLabelValues("api").Inc()
	}
}
