package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"moderation/internal/queue"
)

// Захват сторожа проверяется на настоящем Postgres в internal/queue
// (TestClaimStale*). Здесь — сам проход: сколько раз он зовёт захват, когда
// останавливается и что делает с ошибкой. Без этого проход, который берёт
// ровно один пакет за тик, выглядел бы работающим: очередь из десяти пакетов
// разбиралась бы пять минут вместо одного прохода.

type fakeClaimer struct {
	mu      sync.Mutex
	jobs    []queue.Job
	err     error // возвращается после того, как закончились jobs
	calls   int
	minAges []time.Duration
	// stuck — что вернуть измерению очереди; stuckErr — ошибка измерения.
	stuck    int
	stuckErr error
}

func (f *fakeClaimer) Stuck(context.Context, time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stuck, f.stuckErr
}

func (f *fakeClaimer) ClaimStale(ctx context.Context, minAge time.Duration) (queue.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.minAges = append(f.minAges, minAge)
	if len(f.jobs) == 0 {
		if f.err != nil {
			return queue.Job{}, f.err
		}
		return queue.Job{}, queue.ErrEmpty
	}
	job := f.jobs[0]
	f.jobs = f.jobs[1:]
	return job, nil
}

func newTestWatchdog(claimer staleClaimer, handle func(context.Context, queue.Job)) *watchdog {
	return &watchdog{
		claim: claimer, handle: handle, minAge: 2 * time.Minute,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// Один проход разбирает очередь до конца, а не один пакет.
func TestWatchdogSweepDrainsQueue(t *testing.T) {
	claimer := &fakeClaimer{jobs: []queue.Job{{ItemID: 1}, {ItemID: 2}, {ItemID: 3}}}
	var handled []int64
	wd := newTestWatchdog(claimer, func(_ context.Context, job queue.Job) {
		handled = append(handled, job.ItemID)
	})

	if n := wd.sweep(context.Background()); n != 3 {
		t.Fatalf("обработано %d пакетов, ожидалось 3", n)
	}
	if len(handled) != 3 || handled[0] != 1 || handled[2] != 3 {
		t.Fatalf("обработаны не те пакеты: %v", handled)
	}
	// Порог ожидания обязан доезжать до захвата: без него сторож отбирал бы
	// свежие пакеты у выделенного воркера.
	for _, age := range claimer.minAges {
		if age != 2*time.Minute {
			t.Fatalf("в захват ушёл порог %s, ожидался 2m0s", age)
		}
	}
}

// Пустая очередь — не повод для работы: ровно один вызов захвата и ничего
// больше.
func TestWatchdogSweepEmptyQueue(t *testing.T) {
	claimer := &fakeClaimer{}
	wd := newTestWatchdog(claimer, func(context.Context, queue.Job) {
		t.Fatal("сторож взялся обрабатывать пакет при пустой очереди")
	})
	if n := wd.sweep(context.Background()); n != 0 {
		t.Fatalf("обработано %d пакетов при пустой очереди", n)
	}
	if claimer.calls != 1 {
		t.Fatalf("захват вызван %d раз, ожидался 1", claimer.calls)
	}
}

// Ошибка захвата прекращает проход, а не крутит его в цикле. Сторож живёт в
// процессе API: цикл на недоступной базе съел бы соединения, которые нужны
// обработчикам запросов.
func TestWatchdogSweepStopsOnError(t *testing.T) {
	claimer := &fakeClaimer{jobs: []queue.Job{{ItemID: 7}}, err: errors.New("база недоступна")}
	handled := 0
	wd := newTestWatchdog(claimer, func(context.Context, queue.Job) { handled++ })

	if n := wd.sweep(context.Background()); n != 1 {
		t.Fatalf("обработано %d пакетов, ожидался 1 (до ошибки)", n)
	}
	if handled != 1 {
		t.Fatalf("обработчик вызван %d раз, ожидался 1", handled)
	}
	if claimer.calls != 2 {
		t.Fatalf("захват вызван %d раз, ожидалось 2 (пакет и ошибка)", claimer.calls)
	}
}

// Остановка сервиса прекращает проход: недоразобранная очередь достанется
// следующему запуску, а вот прогон после отмены контекста писал бы шаги
// умирающего процесса.
func TestWatchdogSweepStopsOnCancel(t *testing.T) {
	claimer := &fakeClaimer{jobs: []queue.Job{{ItemID: 1}, {ItemID: 2}, {ItemID: 3}}}
	ctx, cancel := context.WithCancel(context.Background())
	handled := 0
	wd := newTestWatchdog(claimer, func(context.Context, queue.Job) {
		handled++
		cancel() // сервис останавливается посреди прохода
	})

	if n := wd.sweep(ctx); n != 1 {
		t.Fatalf("обработано %d пакетов, ожидался 1 (до отмены)", n)
	}
	if handled != 1 {
		t.Fatalf("обработчик вызван %d раз после отмены, ожидался 1", handled)
	}
}

// Опрос не опускается ниже порога: сторож занимает то же соединение к
// Postgres, что и HTTP-обработчики.
func TestWatchdogIntervalFloor(t *testing.T) {
	claimer := &fakeClaimer{}
	wd := newTestWatchdog(claimer, func(context.Context, queue.Job) {})
	wd.interval = time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	wd.run(ctx)

	if claimer.calls != 0 {
		t.Fatalf("захват вызван %d раз за 300мс — порог опроса %s не применён",
			claimer.calls, minWatchdogInterval)
	}
}
