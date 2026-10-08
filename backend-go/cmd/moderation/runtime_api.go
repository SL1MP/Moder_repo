package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/api"
	"moderation/internal/config"
)

// handlerSlot нужен из-за правила atomic.Value: все Store должны получать
// одно и то же concrete type. Сам http.Handler при разных сборках роутера
// может иметь разные реализации.
type handlerSlot struct {
	http.Handler
}

// swappableHandler оставляет HTTP listener открытым, пока новый набор
// настроек, клиентов и маршрутов собирается в фоне. Уже начатый запрос
// заканчивает работу на прежнем роутере, следующий попадает в новый.
type swappableHandler struct {
	current atomic.Value
}

func newSwappableHandler(initial http.Handler) *swappableHandler {
	h := &swappableHandler{}
	h.current.Store(handlerSlot{Handler: initial})
	return h
}

func (h *swappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.current.Load().(handlerSlot).ServeHTTP(w, r)
}

func (h *swappableHandler) Swap(next http.Handler) {
	h.current.Store(handlerSlot{Handler: next})
}

// managedWatchdog — одна конфигурационная генерация сторожа очереди.
// Отдельный контекст позволяет заменить его при изменении интервалов или
// интеграций, не останавливая HTTP API.
type managedWatchdog struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	wd      *watchdog
	enabled bool
	logger  *slog.Logger
}

func prepareWatchdog(
	parent context.Context,
	cfg *config.Config,
	pool *pgxpool.Pool,
	options *api.Options,
	logger *slog.Logger,
) *managedWatchdog {
	if options.Admin == nil {
		return nil
	}

	worker, err := newPipelineWorker(cfg, pool, logger)
	if err != nil {
		// Маршрут остаётся подключённым и возвращает содержательную 500,
		// вместо 404, которая ошибочно означает «такой функции нет».
		options.Admin.Sweep = func(context.Context) (int, error) {
			return 0, fmt.Errorf("сторож очереди недоступен: %w", err)
		}
		logger.Error("сторож очереди НЕ подготовлен — пакеты разберёт только выделенный воркер",
			"error", err)
		return nil
	}

	wd := newWatchdog(worker, cfg.PipelineWatchdogInterval, cfg.PipelineStuckAfter, logger)
	options.Admin.Sweep = func(ctx context.Context) (int, error) {
		return wd.sweep(ctx), nil
	}
	ctx, cancel := context.WithCancel(parent)
	return &managedWatchdog{
		ctx: ctx, cancel: cancel, done: make(chan struct{}), wd: wd,
		enabled: cfg.PipelineWatchdogEnabled, logger: logger,
	}
}

func (w *managedWatchdog) start() {
	if !w.enabled {
		w.logger.Warn("сторож очереди выключен (PIPELINE_WATCHDOG_ENABLED=false) — " +
			"пакеты разбирает только выделенный воркер; ручной проход остаётся доступен")
		close(w.done)
		return
	}
	go func() {
		defer close(w.done)
		w.wd.run(w.ctx)
	}()
}

func (w *managedWatchdog) stop(timeout time.Duration) {
	w.cancel()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-w.done:
	case <-timer.C:
		w.logger.Warn("сторож очереди не успел завершить активную задачу", "timeout", timeout)
	}
}

// watchdogManager последовательно заменяет поколения: два сторожа с разными
// настройками не должны одновременно пытаться подбирать одну очередь.
type watchdogManager struct {
	mu      sync.Mutex
	current *managedWatchdog
}

func (m *watchdogManager) Replace(next *managedWatchdog, timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		m.current.stop(timeout)
	}
	m.current = next
	if next != nil {
		next.start()
	}
}

func (m *watchdogManager) Stop(timeout time.Duration) {
	m.Replace(nil, timeout)
}

// reloadAPIOnStoredSettings собирает новую конфигурационную генерацию рядом
// со старой и атомарно переключает HTTP-трафик. Поэтому сохранение настроек
// не закрывает listener api-go и nginx не получает окно для 502.
func reloadAPIOnStoredSettings(
	ctx context.Context,
	changed <-chan struct{},
	pool *pgxpool.Pool,
	handler *swappableHandler,
	watchdogs *watchdogManager,
	logger *slog.Logger,
) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-changed:
			}

			logger.Info("web-настройки изменены, собираю новую конфигурацию API без остановки сервиса")
			nextCfg, err := config.Load(os.Getenv)
			if err != nil {
				logger.Error("новая конфигурация API не собрана", "error", err)
				continue
			}
			applyStoredSettings(ctx, pool, nextCfg, logger)
			if ctx.Err() != nil {
				return
			}

			options, _, _ := buildOptions(nextCfg, pool, logger)
			nextWatchdog := prepareWatchdog(ctx, nextCfg, pool, &options, logger)
			nextRouter := api.NewRouter(pool, options)
			if ctx.Err() != nil {
				return
			}

			// Старый API продолжает обслуживать запросы, пока сторож завершает
			// активный пакет. Само переключение handler — атомарная операция.
			watchdogs.Replace(nextWatchdog, 10*time.Second)
			handler.Swap(nextRouter)
			logger.Info("web-настройки применены к API без перезапуска")
		}
	}()
}
