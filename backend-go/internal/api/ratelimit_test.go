package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// newTestLimiter — ограничитель с управляемыми часами: проверять окно
// настоящим временем значит либо спать в тесте, либо не проверять его вовсе.
func newTestLimiter(limit int, now *time.Time) *rateLimiter {
	return &rateLimiter{
		limit: limit, window: time.Minute,
		buckets: map[string]*rateBucket{},
		now:     func() time.Time { return *now },
	}
}

// TestRateLimitAllowsUpToLimit — лимит пропускает ровно столько, сколько
// заявлено, и отказывает следующему.
func TestRateLimitAllowsUpToLimit(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	rl := newTestLimiter(3, &now)

	for i := 1; i <= 3; i++ {
		if ok, _ := rl.allow("petrov"); !ok {
			t.Fatalf("запрос %d отклонён, а лимит 3", i)
		}
	}
	ok, retry := rl.allow("petrov")
	if ok {
		t.Fatal("четвёртый запрос прошёл при лимите 3")
	}
	// Без Retry-After клиент не знает, когда повторять, и начинает долбиться,
	// усугубляя ровно то, от чего лимит защищает.
	if retry <= 0 || retry > time.Minute {
		t.Errorf("время до повтора = %v", retry)
	}
}

// TestRateLimitIsPerUser — лимит считается по пользователю, а не общий.
//
// За одним адресом сидит весь офис через корпоративный прокси; общий счётчик
// означал бы, что активный разработчик перекрывает кислород остальным.
func TestRateLimitIsPerUser(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	rl := newTestLimiter(2, &now)

	rl.allow("petrov")
	rl.allow("petrov")
	if ok, _ := rl.allow("petrov"); ok {
		t.Fatal("петров исчерпал лимит, но прошёл")
	}
	if ok, _ := rl.allow("ivanov"); !ok {
		t.Error("иванов отклонён из-за чужого лимита")
	}
}

// TestRateLimitWindowSlides — через окно лимит снова доступен.
func TestRateLimitWindowSlides(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	rl := newTestLimiter(2, &now)

	rl.allow("petrov")
	rl.allow("petrov")
	if ok, _ := rl.allow("petrov"); ok {
		t.Fatal("лимит не сработал")
	}

	// Ровно через два окна прошлое уже не влияет вовсе.
	now = now.Add(2 * time.Minute)
	if ok, _ := rl.allow("petrov"); !ok {
		t.Error("через два окна лимит всё ещё держит")
	}
}

// TestRateLimitNoBurstAtWindowBoundary — на границе окна нельзя выбрать два
// лимита подряд.
//
// Известная дыра счётчиков с фиксированным окном: 30 запросов в конце одной
// минуты и 30 в начале следующей — это 60 за две секунды. Взвешенная сумма
// по предыдущему окну её закрывает, и проверка здесь именно на это.
func TestRateLimitNoBurstAtWindowBoundary(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	rl := newTestLimiter(10, &now)

	// Выбираем весь лимит в самом конце окна.
	now = now.Add(59 * time.Second)
	for i := 0; i < 10; i++ {
		if ok, _ := rl.allow("petrov"); !ok {
			t.Fatalf("запрос %d отклонён внутри лимита", i)
		}
	}

	// Сразу после границы окна: предыдущее окно ещё весит почти единицу,
	// поэтому второй десяток проходить не должен.
	now = now.Add(2 * time.Second)
	if ok, _ := rl.allow("petrov"); ok {
		t.Error("на границе окна пропущен второй лимит подряд — " +
			"за три секунды вышло бы 20 запросов при лимите 10")
	}
}

// TestRateLimitSweepDropsColdBuckets — записи остывших пользователей
// выбрасываются. Без уборки карта растёт по записи на каждого когда-либо
// заходившего и не уменьшается никогда.
func TestRateLimitSweepDropsColdBuckets(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	rl := newTestLimiter(5, &now)

	rl.allow("petrov")
	if len(rl.buckets) != 1 {
		t.Fatalf("записей = %d", len(rl.buckets))
	}

	// Уборка идёт не чаще раза в пять минут, поэтому двигаем время дальше.
	now = now.Add(10 * time.Minute)
	rl.allow("ivanov")

	if _, ok := rl.buckets["petrov"]; ok {
		t.Error("остывшая запись не убрана — карта растёт бесконечно")
	}
	if _, ok := rl.buckets["ivanov"]; !ok {
		t.Error("свежая запись убрана вместе с остывшими")
	}
}

// TestRateLimitDisabled — нулевой лимит отдаёт обработчик КАК ЕСТЬ, без
// обёртки: ветка «лимита нет» не должна стоить блокировки на каждом запросе.
func TestRateLimitDisabled(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	got := NewRateLimit(0)(handler)
	if fmt.Sprintf("%p", got) != fmt.Sprintf("%p", handler) {
		t.Error("выключенный лимит обернул обработчик — значит, считает на каждом запросе")
	}
}
