package main

import (
	"context"
	"log/slog"
	"time"

	"moderation/internal/config"
	"moderation/internal/repo"
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
// выводит его из выборки. Упавший прогон повторяется — но не на каждом тике
// подряд, а с нарастающей паузой (см. retryAfter): пакет, который не
// сканируется в принципе (артефакт удалён из реестра, сеть до реестра
// закрыта), иначе занимал бы место в пачке вечно и не пускал бы за собой
// остальные.
type watcher struct {
	repo        *repo.Repo
	stores      *stores
	cfg         *config.Config
	logger      *slog.Logger
	interval    time.Duration
	batch       int
	itemTimeout time.Duration

	// failed — когда можно снова пробовать упавший пакет. Только в памяти:
	// после перезапуска сервиса разумно попробовать всё заново, а тащить ради
	// этого таблицу в базу — переусложнение для конструкции переходного
	// периода.
	failed map[int64]time.Time
	// attempts — сколько раз подряд пакет падал, для длины паузы.
	attempts map[int64]int
}

// retryAfter — пауза перед следующей попыткой по упавшему пакету: 1, 2, 4 …
// интервала наблюдателя, но не дольше часа. Первая повторная попытка остаётся
// быстрой (сеть моргнула), а безнадёжный пакет перестаёт занимать пачку.
func (w *watcher) retryAfter(attempt int) time.Duration {
	const maxBackoff = time.Hour
	delay := w.interval
	for i := 1; i < attempt && delay < maxBackoff; i++ {
		delay *= 2
	}
	if delay > maxBackoff {
		delay = maxBackoff
	}
	return delay
}

func (w *watcher) run(ctx context.Context) {
	if w.failed == nil {
		w.failed = map[int64]time.Time{}
		w.attempts = map[int64]int{}
	}
	if w.itemTimeout <= 0 {
		w.itemTimeout = 20 * time.Minute
	}
	// Длительности пишутся строкой: slog кладёт time.Duration в JSON как
	// наносекунды, и «60000000000» в логе читать невозможно.
	w.logger.Info("наблюдатель сканирования запущен",
		"интервал", w.interval.String(), "пакетов за раз", w.batch,
		"таймаут на пакет", w.itemTimeout.String())

	// Первый проход сразу, не дожидаясь тика: после перезапуска сервиса
	// накопившийся хвост разбирается без лишней паузы.
	w.tick(ctx, true)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("наблюдатель сканирования остановлен")
			return
		case <-ticker.C:
			w.tick(ctx, false)
		}
	}
}

// tick — один проход. first=true у самого первого: его итог пишется в лог
// всегда, даже когда сканировать нечего. Без этого «наблюдатель жив, работы
// нет» и «наблюдатель не запустился» выглядят в логах одинаково — никак, — и
// разбирательство начинается с чтения исходников вместо чтения логов.
func (w *watcher) tick(ctx context.Context, first bool) {
	items, err := w.repo.ItemsAwaitingScan(ctx, w.batch)
	if err != nil {
		w.logger.Error("наблюдатель: выборка пакетов не удалась", "error", err)
		return
	}

	now := time.Now()
	ready := make([]int64, 0, len(items))
	postponed := 0
	for _, id := range items {
		if until, ok := w.failed[id]; ok && now.Before(until) {
			postponed++
			continue
		}
		ready = append(ready, id)
	}

	if len(ready) == 0 {
		if first || postponed > 0 {
			w.logger.Info("наблюдатель: сканировать нечего",
				"без отчётов", len(items), "отложено после ошибок", postponed)
		}
		return
	}
	w.logger.Info("наблюдатель: найдены пакеты без отчётов",
		"пакетов", len(ready), "отложено после ошибок", postponed)

	for _, itemID := range ready {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Прогон одного пакета ограничен по времени отдельно: зависший сканер
		// не должен останавливать разбор очереди целиком.
		itemCtx, cancel := context.WithTimeout(ctx, w.itemTimeout)
		err := scanOne(itemCtx, w.repo, w.stores, w.cfg, itemID, w.logger)
		cancel()
		if err != nil {
			w.attempts[itemID]++
			delay := w.retryAfter(w.attempts[itemID])
			w.failed[itemID] = time.Now().Add(delay)
			w.logger.Error("наблюдатель: пакет не просканирован",
				"item", itemID, "попытка", w.attempts[itemID],
				"следующая попытка через", delay.String(), "error", err)
			continue
		}
		delete(w.failed, itemID)
		delete(w.attempts, itemID)
	}
}
