package api

import (
	"net/http"
	"sync"
	"time"
)

// Ограничение частоты запросов.
//
// Порт RATE_LIMIT_REQUESTS_PER_MINUTE из python-версии, который go-версия до
// сих пор игнорировала: настройка в .env была, а поведения за ней не стояло.
//
// Считаем по ПОЛЬЗОВАТЕЛЮ, а не по адресу. За одним адресом сидит весь офис
// через корпоративный прокси, и лимит на адрес означал бы, что активный
// разработчик перекрывает кислород всем остальным. Запросы без опознанного
// пользователя (до аутентификации: health, метрики, /auth/config) не считаются
// вовсе — иначе один неавторизованный клиент выбирал бы общий лимит.
//
// Алгоритм — скользящее окно на счётчиках: два ведра по половине окна,
// текущее и предыдущее, с линейной интерполяцией. Точность достаточная, а
// память постоянная — в отличие от списка отметок времени на каждый запрос,
// который при всплеске растёт вместе с ним.

// rateLimiter — состояние ограничителя.
type rateLimiter struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	buckets map[string]*rateBucket
	// now подменяется в тестах.
	now func() time.Time
	// lastSweep — когда последний раз убирали остывшие записи.
	lastSweep time.Time
}

type rateBucket struct {
	// startedAt — начало текущего окна.
	startedAt time.Time
	current   int
	previous  int
}

// NewRateLimit собирает middleware, пропускающее не больше limit запросов в
// минуту от одного пользователя.
//
// limit <= 0 — ограничение выключено, и middleware возвращается пустым: так
// ветка «лимита нет» не стоит ни одной блокировки на каждом запросе.
func NewRateLimit(limit int) func(http.Handler) http.Handler {
	if limit <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	rl := &rateLimiter{
		limit: limit, window: time.Minute,
		buckets: make(map[string]*rateBucket),
	}
	return rl.middleware
}

func (rl *rateLimiter) clock() time.Time {
	if rl.now != nil {
		return rl.now()
	}
	return time.Now()
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := CurrentUser(r.Context())
		if !ok || user == nil {
			// Неопознанный запрос не считаем: см. комментарий к пакету.
			next.ServeHTTP(w, r)
			return
		}
		allowed, retryAfter := rl.allow(user.Username)
		if !allowed {
			// Retry-After обязателен: без него клиент не знает, когда можно
			// повторить, и начинает долбиться, усугубляя ровно то, от чего
			// лимит защищает.
			w.Header().Set("Retry-After", retryAfterSeconds(retryAfter))
			writeError(w, r, errTooManyRequests(
				"Слишком много запросов. Повторите через "+retryAfterSeconds(retryAfter)+" с"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow — можно ли выполнить запрос. Второе значение — через сколько повторять.
func (rl *rateLimiter) allow(key string) (bool, time.Duration) {
	now := rl.clock()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sweep(now)

	bucket, ok := rl.buckets[key]
	if !ok {
		bucket = &rateBucket{startedAt: now}
		rl.buckets[key] = bucket
	}

	// Сдвиг окна. Если прошло больше двух окон, предыдущее уже не влияет —
	// обнуляем оба, иначе «хвост» недельной давности считался бы недавним.
	switch elapsed := now.Sub(bucket.startedAt); {
	case elapsed >= 2*rl.window:
		bucket.startedAt, bucket.current, bucket.previous = now, 0, 0
	case elapsed >= rl.window:
		bucket.startedAt = bucket.startedAt.Add(rl.window)
		bucket.previous, bucket.current = bucket.current, 0
	}

	// Взвешенная сумма: чем дальше мы в текущем окне, тем меньше вклад
	// предыдущего. Без этого на границе окна пропускались бы два лимита
	// подряд — известная дыра счётчиков с фиксированным окном.
	elapsed := now.Sub(bucket.startedAt)
	weight := 1 - float64(elapsed)/float64(rl.window)
	if weight < 0 {
		weight = 0
	}
	used := float64(bucket.previous)*weight + float64(bucket.current)

	if used >= float64(rl.limit) {
		return false, rl.window - elapsed
	}
	bucket.current++
	return true, 0
}

// sweep выбрасывает записи, по которым давно ничего не было. Без неё карта
// растёт по одной записи на каждого когда-либо заходившего пользователя и не
// уменьшается никогда.
func (rl *rateLimiter) sweep(now time.Time) {
	const sweepEvery = 5 * time.Minute
	if now.Sub(rl.lastSweep) < sweepEvery {
		return
	}
	rl.lastSweep = now
	for key, bucket := range rl.buckets {
		if now.Sub(bucket.startedAt) >= 2*rl.window {
			delete(rl.buckets, key)
		}
	}
}

func retryAfterSeconds(d time.Duration) string {
	seconds := int(d.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return itoa(seconds)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
