package queue_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/queue"
	"moderation/internal/repo"
)

// Очередь проверяется только на настоящем Postgres: вся её суть — поведение
// SQL при конкуренции (FOR UPDATE SKIP LOCKED, видимость транзакций,
// LISTEN/NOTIFY). Мок доказал бы лишь то, что мок написан так же, как код.

func setup(t *testing.T) (*queue.Queue, *repo.Repo, func()) {
	t.Helper()
	dsn := os.Getenv("MODERATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MODERATION_TEST_POSTGRES_DSN не задан — пропускаю интеграционный тест (см. docs/testing.md)")
	}
	pool, err := db.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("подключение к тестовому Postgres: %v", err)
	}
	return queue.New(pool, time.Minute), repo.New(pool), func() { pool.Close() }
}

// parkOlder убирает из очереди всё, что лежало в ней до нашего пакета.
//
// Тестовая база общая и переиспользуется, а Claim берёт самый старый
// подходящий пакет — без этого тест проверял бы чужие строки, оставшиеся от
// прошлых прогонов. Отсекаем строго по id меньше нашего: идентификаторы
// выдаёт последовательность, поэтому всё, что другие пакеты тестов создадут
// параллельно, получит id больше нашего и затронуто не будет.
func parkOlder(t *testing.T, r *repo.Repo, itemID int64) {
	t.Helper()
	_, err := r.Pool().Exec(context.Background(), `
		UPDATE request_item SET status = 'failed'
		WHERE id < $1 AND status IN ('queued', 'running')
	`, itemID)
	if err != nil {
		t.Fatalf("очистка очереди перед тестом: %v", err)
	}
}

// newItem заводит пакет заявки в нужном статусе и возвращает его id.
func newItem(t *testing.T, r *repo.Repo, status string) int64 {
	t.Helper()
	ctx := context.Background()
	slug := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())

	user, err := r.GetOrCreateUser(ctx, "q-"+slug, "Очередь")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := r.GetOrCreatePackage(ctx, "pypi", "q-"+slug, "q-"+slug)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: user.ID, Manager: "pypi", Status: "pending", Source: "api", Warnings: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req.ID, PackageVersionID: ver.ID,
		RequestedName: "q", RequestedVersion: "1.0.0",
		DependencyKind: "direct", Status: status,
	})
	if err != nil {
		t.Fatal(err)
	}
	return item.ID
}

// Ни один пакет не достаётся двум воркерам. Это главное свойство очереди: без
// него пакет проверяется дважды, и два прогона пишут его шаги вперемешку.
//
// Пакетов заметно больше, чем воркеров, и каждый воркер разбирает очередь до
// конца: с одним пакетом и одним заходом на воркера столкновения почти не
// случаются, и тест проходил бы даже на заведомо неэксклюзивном захвате —
// это проверено мутацией.
func TestClaimIsExclusive(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	const items = 40
	ids := make(map[int64]bool, items)
	var first int64
	for i := 0; i < items; i++ {
		id := newItem(t, r, "queued")
		if first == 0 {
			first = id
		}
		ids[id] = true
	}
	parkOlder(t, r, first)

	const workers = 8
	var ready, wg sync.WaitGroup
	start := make(chan struct{})
	claimed := make([][]int64, workers)
	ready.Add(workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			ready.Done()
			<-start
			for {
				job, err := q.Claim(ctx)
				if errors.Is(err, queue.ErrEmpty) {
					return
				}
				if err != nil {
					t.Errorf("воркер %d: %v", i, err)
					return
				}
				claimed[i] = append(claimed[i], job.ItemID)
			}
		}(i)
	}
	ready.Wait()
	close(start)
	wg.Wait()

	seen := map[int64]int{}
	total := 0
	for _, batch := range claimed {
		for _, id := range batch {
			seen[id]++
			total++
		}
	}
	for id, times := range seen {
		if times > 1 {
			t.Errorf("пакет #%d захвачен %d раз", id, times)
		}
	}
	for id := range ids {
		if seen[id] == 0 {
			t.Errorf("пакет #%d не достался никому", id)
		}
	}
	if t.Failed() {
		t.Fatalf("всего захватов %d при %d пакетах", total, items)
	}
}

// Пакет, который уже кто-то взял, второй раз не выдаётся.
func TestRunningItemNotClaimedWhileAlive(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()
	itemID := newItem(t, r, "queued")
	parkOlder(t, r, itemID)

	first, err := q.Claim(ctx)
	if err != nil || first.ItemID != itemID {
		t.Fatalf("первый захват: %v (%d)", err, first.ItemID)
	}
	// Второй заход не должен вернуть этот же пакет.
	for {
		job, err := q.Claim(ctx)
		if errors.Is(err, queue.ErrEmpty) {
			break
		}
		if err != nil {
			t.Fatalf("второй захват: %v", err)
		}
		if job.ItemID == itemID {
			t.Fatal("пакет выдан второй раз, пока прогон жив")
		}
	}
}

// Прогон, который упал вместе с процессом, должен быть подобран: строка
// перестала обновляться, значит хозяина у неё нет.
func TestAbandonedRunningItemIsReclaimed(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()
	itemID := newItem(t, r, "queued")
	parkOlder(t, r, itemID)

	if _, err := q.Claim(ctx); err != nil {
		t.Fatalf("захват: %v", err)
	}
	// Отматываем отметку жизни назад — так выглядит процесс, который упал.
	if _, err := r.Pool().Exec(ctx,
		`UPDATE request_item SET updated_at = now() - interval '10 minutes' WHERE id = $1`,
		itemID); err != nil {
		t.Fatal(err)
	}

	job, err := q.Claim(ctx)
	if err != nil {
		t.Fatalf("перехват брошенного: %v", err)
	}
	if job.ItemID != itemID {
		t.Fatalf("перехвачен пакет #%d вместо #%d", job.ItemID, itemID)
	}
}

// Heartbeat защищает живой прогон от перехвата и честно говорит, что строку
// уже отобрали.
func TestHeartbeat(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()
	itemID := newItem(t, r, "queued")
	parkOlder(t, r, itemID)
	if _, err := q.Claim(ctx); err != nil {
		t.Fatal(err)
	}

	alive, err := q.Heartbeat(ctx, itemID)
	if err != nil || !alive {
		t.Fatalf("живой прогон: alive=%v err=%v", alive, err)
	}

	// Кто-то перевёл пакет в другой статус — прогон обязан это заметить и
	// прекратиться, а не дописывать шаги поверх чужой работы.
	if _, err := r.Pool().Exec(ctx,
		`UPDATE request_item SET status = 'approved' WHERE id = $1`, itemID); err != nil {
		t.Fatal(err)
	}
	alive, err = q.Heartbeat(ctx, itemID)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if alive {
		t.Fatal("heartbeat обязан сообщить, что прогон больше не владеет пакетом")
	}
}

func TestEnqueueSetsResumeStep(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()
	itemID := newItem(t, r, "awaiting_security")
	parkOlder(t, r, itemID)

	if err := q.Enqueue(ctx, itemID, "download"); err != nil {
		t.Fatalf("постановка в очередь: %v", err)
	}
	job, err := q.Claim(ctx)
	if err != nil {
		t.Fatalf("захват: %v", err)
	}
	if job.ItemID != itemID || job.FromStep != "download" {
		t.Fatalf("получено %+v, ожидался пакет #%d с шага download", job, itemID)
	}

	// Отметка снимается после прогона: иначе следующий запуск того же пакета
	// молча начался бы с середины.
	if err := q.ClearResumeStep(ctx, itemID); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, itemID, ""); err != nil {
		t.Fatal(err)
	}
	job, err = q.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if job.FromStep != "" {
		t.Fatalf("шаг возобновления не сброшен: %q", job.FromStep)
	}
}

// Воркер должен просыпаться от уведомления, а не ждать следующего опроса:
// иначе заявка стоит до истечения интервала при пустой очереди.
func TestWaitWakesOnNotify(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()
	itemID := newItem(t, r, "awaiting_legal")

	done := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		_ = q.Wait(ctx, 10*time.Second)
		done <- time.Since(started)
	}()

	time.Sleep(200 * time.Millisecond) // дать подписке встать
	if err := q.Enqueue(ctx, itemID, ""); err != nil {
		t.Fatalf("постановка в очередь: %v", err)
	}

	select {
	case elapsed := <-done:
		if elapsed > 3*time.Second {
			t.Fatalf("пробуждение заняло %s — похоже, сработал таймаут, а не уведомление", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("воркер не проснулся по уведомлению")
	}
}

// Истечение таймаута — не ошибка: это обычный тик опроса при пустой очереди.
func TestWaitTimeoutIsNotAnError(t *testing.T) {
	q, _, cleanup := setup(t)
	defer cleanup()
	if err := q.Wait(context.Background(), 300*time.Millisecond); err != nil {
		t.Fatalf("истечение таймаута не должно быть ошибкой: %v", err)
	}
}

func TestDepth(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()
	newItem(t, r, "queued")

	queued, _, err := q.Depth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if queued == 0 {
		t.Fatal("в очереди должен быть хотя бы один пакет")
	}
}

// backdate сдвигает отметку пакета в прошлое: так проверяется ожидание в
// очереди без того, чтобы тест реально ждал минуты.
func backdate(t *testing.T, r *repo.Repo, itemID int64, d time.Duration) {
	t.Helper()
	_, err := r.Pool().Exec(context.Background(),
		`UPDATE request_item SET updated_at = now() - $2::interval WHERE id = $1`,
		itemID, fmt.Sprintf("%d seconds", int(d.Seconds())))
	if err != nil {
		t.Fatalf("сдвиг отметки пакета: %v", err)
	}
}

// Свежий пакет сторожу не виден: сначала работу должен получить выделенный
// воркер. Без этого свойства сторож в процессе API отбирал бы пакеты у
// воркера и гонял бы конвейер внутри HTTP-сервиса всегда, а не только когда
// воркера нет.
func TestClaimStaleSkipsFreshItems(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	itemID := newItem(t, r, "queued")
	parkOlder(t, r, itemID)

	if _, err := q.ClaimStale(ctx, time.Minute); !errors.Is(err, queue.ErrEmpty) {
		t.Fatalf("сторож забрал свежий пакет: err = %v", err)
	}
	// Обычный захват его при этом видит — иначе тест выше проходил бы и на
	// пустой очереди.
	job, err := q.Claim(ctx)
	if err != nil {
		t.Fatalf("выделенный воркер не увидел свежий пакет: %v", err)
	}
	if job.ItemID != itemID {
		t.Fatalf("забран не тот пакет: %d, ожидался %d", job.ItemID, itemID)
	}
}

// Пакет, пролежавший дольше порога, сторож забирает. Это и есть страховка:
// выделенного воркера нет — работу делает процесс API.
func TestClaimStaleTakesWaitingItem(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	itemID := newItem(t, r, "queued")
	parkOlder(t, r, itemID)
	backdate(t, r, itemID, 5*time.Minute)

	job, err := q.ClaimStale(ctx, time.Minute)
	if err != nil {
		t.Fatalf("сторож не забрал залежавшийся пакет: %v", err)
	}
	if job.ItemID != itemID {
		t.Fatalf("забран не тот пакет: %d, ожидался %d", job.ItemID, itemID)
	}

	// И забирает ровно один раз: захват у сторожа и воркера общий.
	if _, err := q.ClaimStale(ctx, time.Minute); !errors.Is(err, queue.ErrEmpty) {
		t.Fatalf("тот же пакет достался сторожу дважды: err = %v", err)
	}
	if _, err := q.Claim(ctx); !errors.Is(err, queue.ErrEmpty) {
		t.Fatalf("пакет, забранный сторожем, достался и воркеру: err = %v", err)
	}
}

// Брошенный прогон (`running`, отметка о жизни не обновляется) сторож
// подбирает по своему порогу — StaleAfter, а не minAge. Иначе упавший на
// середине воркер оставлял бы пакет висеть, пока кто-нибудь не запустит
// второго воркера руками.
func TestClaimStaleReclaimsAbandonedRun(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	itemID := newItem(t, r, "running")
	parkOlder(t, r, itemID)
	backdate(t, r, itemID, 5*time.Minute) // StaleAfter в setup — минута

	job, err := q.ClaimStale(ctx, time.Hour) // порог ожидания заведомо больше
	if err != nil {
		t.Fatalf("сторож не подобрал брошенный прогон: %v", err)
	}
	if job.ItemID != itemID {
		t.Fatalf("забран не тот пакет: %d, ожидался %d", job.ItemID, itemID)
	}
}

// Живой прогон сторож не отбирает: пока отметка обновляется, пакетом
// занимается другой процесс.
func TestClaimStaleLeavesLiveRunAlone(t *testing.T) {
	q, r, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	itemID := newItem(t, r, "running")
	parkOlder(t, r, itemID)

	if _, err := q.ClaimStale(ctx, time.Second); !errors.Is(err, queue.ErrEmpty) {
		t.Fatalf("сторож отобрал живой прогон: err = %v", err)
	}
}
