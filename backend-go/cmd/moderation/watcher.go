package main

import (
	"context"
	"log/slog"
	"time"

	"moderation/internal/config"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

// Фоновый наблюдатель: сам находит пакеты заявок, по которым отчётов ещё нет,
// и прогоняет по ним сканеры содержимого.
//
// Зачем он нужен именно сейчас. Заявки заводит и ведёт python-конвейер, а
// отчёты умеет делать только Go. Без наблюдателя приходилось после каждой
// заявки вручную звать `moderation scan`, то есть отчёты появлялись только у
// тех пакетов, про которые не забыли. Это ровно тот случай, когда проверка
// «есть, но её надо не забыть запустить» хуже отсутствующей: ей начинают
// доверять.
//
// Наблюдатель — конструкция ПЕРЕХОДНОГО периода. Когда Go получит собственный
// API заявок и конвейер целиком, сканирование станет обычным шагом, а этот
// файл уедет. Поэтому он сознательно прост: ни очереди, ни блокировок, ни
// повторов — один запрос раз в интервал и последовательный прогон.
//
// Повторно один и тот же пакет не сканируется: наличие строки scan_report
// выводит его из выборки. Поэтому упавший прогон будет повторён на следующем
// тике — это и есть весь механизм повторов.
type watcher struct {
	repo     *repo.Repo
	storage  storage.Store
	cfg      *config.Config
	logger   *slog.Logger
	interval time.Duration
	batch    int
}

func (w *watcher) run(ctx context.Context) {
	w.logger.Info("наблюдатель сканирования запущен",
		"интервал", w.interval, "пакетов за раз", w.batch)

	// Первый проход сразу, не дожидаясь тика: после перезапуска сервиса
	// накопившийся хвост разбирается без лишней паузы.
	w.tick(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("наблюдатель сканирования остановлен")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *watcher) tick(ctx context.Context) {
	items, err := w.repo.ItemsAwaitingScan(ctx, w.batch)
	if err != nil {
		w.logger.Error("наблюдатель: выборка пакетов не удалась", "error", err)
		return
	}
	if len(items) == 0 {
		return
	}
	w.logger.Info("наблюдатель: найдены пакеты без отчётов", "пакетов", len(items))

	for _, itemID := range items {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Прогон одного пакета ограничен по времени отдельно: зависший сканер
		// не должен останавливать разбор очереди целиком.
		itemCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		err := scanOne(itemCtx, w.repo, w.storage, w.cfg, itemID, w.logger)
		cancel()
		if err != nil {
			// Не фатально: строки scan_report не появилось, значит пакет
			// попадёт в выборку снова на следующем тике.
			w.logger.Error("наблюдатель: пакет не просканирован", "item", itemID, "error", err)
		}
	}
}
