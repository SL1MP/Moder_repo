package registry

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"moderation/internal/metrics"
)

// Повторы и предохранитель на вызовах к реестрам.
//
// Закрывает долг, отмеченный в status.md: в Go повторялся весь прогон пакета
// целиком, а отдельный запрос при 502 — нет. Разница дорогая. Прогон пакета
// включает скачивание артефакта (у docker — сотни мегабайт) и обращение в
// песочницу; повторять всё это из-за одного моргнувшего запроса к реестру
// метаданных означает платить минутами за секундную неполадку.
//
// Две разные вещи, и путать их нельзя:
//
//	повтор        — реестр моргнул, пробуем ещё раз через паузу;
//	предохранитель — реестр лежит, и долбиться в него бессмысленно: каждая
//	                 попытка тратит таймаут, а пакетов в очереди сотня.
//
// Предохранитель нужен именно из-за очереди: без него упавший реестр
// превращает разбор очереди в последовательное ожидание таймаута на каждом
// пакете, и сервис выглядит зависшим, хотя работает ровно как написано.

// ErrCircuitOpen — предохранитель разомкнут: к реестру сейчас не ходим.
//
// Отдельная ошибка, а не обычный сбой сети: шаг конвейера обязан сказать
// человеку правду — «реестр недоступен, повторим позже», а не «версия не
// найдена».
var ErrCircuitOpen = errors.New("обращения к реестру временно приостановлены")

// RetryPolicy — сколько раз и с какими паузами повторять.
type RetryPolicy struct {
	// Attempts — общее число попыток, включая первую. 1 и меньше — без повторов.
	Attempts int
	// BaseDelay — пауза перед вторым обращением; дальше удваивается.
	BaseDelay time.Duration
	// MaxDelay — потолок паузы.
	MaxDelay time.Duration
}

// DefaultRetryPolicy — значения, с которыми сервис работает по умолчанию.
//
// Три попытки, а не больше: реестр, не ответивший трижды за полторы секунды,
// не ответит и на четвёртый раз, а очередь ждёт.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{Attempts: 3, BaseDelay: 300 * time.Millisecond, MaxDelay: 3 * time.Second}
}

// BreakerPolicy — когда размыкать предохранитель и когда пробовать снова.
type BreakerPolicy struct {
	// FailureThreshold — сколько подряд неудач размыкают предохранитель.
	FailureThreshold int
	// OpenFor — сколько держать разомкнутым, прежде чем пустить одну пробу.
	OpenFor time.Duration
}

func DefaultBreakerPolicy() BreakerPolicy {
	return BreakerPolicy{FailureThreshold: 5, OpenFor: 30 * time.Second}
}

// ResilientDoer — клиент с повторами и предохранителем.
//
// Обёртка над Doer, а не правка каждого плагина: плагины отвечают за формат
// ответа реестра, а не за сетевые неполадки, и повтор, размазанный по десяти
// плагинам, в одном из них обязательно окажется забыт.
type ResilientDoer struct {
	Next    Doer
	Retry   RetryPolicy
	Breaker BreakerPolicy

	mu    sync.Mutex
	state map[string]*breakerState
	// now и sleep подменяются в тестах: проверять паузы настоящим временем
	// значит либо спать в тесте, либо не проверять их вовсе.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

type breakerState struct {
	failures int
	openedAt time.Time
	// halfOpen — пущена одна пробная попытка; результат решает, замкнуть
	// предохранитель обратно или снова разомкнуть.
	halfOpen bool
}

// NewResilientDoer собирает клиент. next обязателен.
func NewResilientDoer(next Doer, retry RetryPolicy, breaker BreakerPolicy) *ResilientDoer {
	return &ResilientDoer{
		Next: next, Retry: retry, Breaker: breaker,
		state: map[string]*breakerState{},
	}
}

func (d *ResilientDoer) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

func (d *ResilientDoer) wait(ctx context.Context, delay time.Duration) error {
	if d.sleep != nil {
		return d.sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (d *ResilientDoer) Do(req *http.Request) (*http.Response, error) {
	service := serviceOf(req.URL)

	if open, until := d.locked(service); open {
		metrics.ObserveExternal(service, "circuit_open")
		return nil, fmt.Errorf("%w: %s, следующая попытка не раньше чем через %s",
			ErrCircuitOpen, service, until.Round(time.Second))
	}

	attempts := d.Retry.Attempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		resp, err := d.Next.Do(req)
		switch {
		case err == nil && !retryableStatus(resp.StatusCode):
			// Ответ получен и он окончательный — в том числе 404: «версии
			// нет» это ответ реестра, а не его недоступность, и повторять
			// такое бессмысленно.
			d.succeeded(service)
			metrics.ObserveExternal(service, "ok")
			return resp, nil
		case err == nil:
			// 429, 502, 503, 504 — реестр есть, но сейчас не отвечает по делу.
			lastErr = fmt.Errorf("реестр ответил %d", resp.StatusCode)
			// Тело закрываем: иначе подключение не вернётся в пул, и повторы
			// исчерпают его за несколько пакетов.
			_ = resp.Body.Close()
		case !retryableError(err):
			// Ошибка не про сеть (например, отменённый контекст): повторять
			// нечего, и записывать реестру неудачу тоже не за что.
			metrics.ObserveExternal(service, "error")
			return nil, err
		default:
			lastErr = err
		}

		if attempt == attempts {
			break
		}
		if err := d.wait(req.Context(), d.delay(attempt)); err != nil {
			return nil, err
		}
		// Повтор — это новый запрос: тело у GET пустое, но контекст мог
		// истечь, и продолжать в этом случае незачем.
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
	}

	d.failed(service)
	metrics.ObserveExternal(service, "failed")
	return nil, fmt.Errorf("реестр %s не ответил за %d попыток: %w", service, attempts, lastErr)
}

// delay — пауза перед попыткой attempt+1, с разбросом.
//
// Разброс обязателен: без него сотня пакетов, упёршихся в один упавший
// реестр, повторяет запросы синхронно и добивает его ровно в тот момент,
// когда он поднимается.
func (d *ResilientDoer) delay(attempt int) time.Duration {
	base := d.Retry.BaseDelay
	if base <= 0 {
		base = 300 * time.Millisecond
	}
	delay := base << (attempt - 1)
	if max := d.Retry.MaxDelay; max > 0 && delay > max {
		delay = max
	}
	// ±20%.
	jitter := time.Duration(rand.Int63n(int64(delay/5)*2+1)) - delay/5 //nolint:gosec // не крипто
	return delay + jitter
}

// --------------------------------------------------------------------------- предохранитель

// locked — разомкнут ли предохранитель. Второе значение — сколько ещё ждать.
func (d *ResilientDoer) locked(service string) (bool, time.Duration) {
	threshold := d.Breaker.FailureThreshold
	if threshold <= 0 {
		return false, 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.state[service]
	if !ok || state.openedAt.IsZero() {
		return false, 0
	}

	elapsed := d.clock().Sub(state.openedAt)
	if elapsed < d.Breaker.OpenFor {
		return true, d.Breaker.OpenFor - elapsed
	}
	// Срок вышел: пускаем ОДНУ пробную попытку. Пустить все сразу значило бы
	// обрушить на едва поднявшийся реестр всю накопленную очередь.
	if state.halfOpen {
		return true, d.Breaker.OpenFor
	}
	state.halfOpen = true
	metrics.CircuitState.WithLabelValues(service).Set(2)
	return false, 0
}

func (d *ResilientDoer) succeeded(service string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.state[service]
	if !ok {
		return
	}
	if state.failures > 0 || !state.openedAt.IsZero() {
		metrics.CircuitState.WithLabelValues(service).Set(0)
	}
	state.failures, state.openedAt, state.halfOpen = 0, time.Time{}, false
}

func (d *ResilientDoer) failed(service string) {
	threshold := d.Breaker.FailureThreshold
	if threshold <= 0 {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.state[service]
	if !ok {
		state = &breakerState{}
		d.state[service] = state
	}
	state.failures++

	// Пробная попытка не удалась — размыкаем заново, отсчёт срока с нуля.
	if state.halfOpen {
		state.halfOpen, state.openedAt = false, d.clock()
		metrics.CircuitState.WithLabelValues(service).Set(1)
		return
	}
	if state.failures >= threshold {
		state.openedAt = d.clock()
		metrics.CircuitState.WithLabelValues(service).Set(1)
	}
}

// --------------------------------------------------------------------------- классификация

// retryableStatus — коды, при которых повтор осмыслен.
//
// 404 сюда не входит намеренно: «версии нет» — ответ реестра, а не его
// недоступность, и повторять его значит втрое замедлить самый частый случай
// ошибки пользователя (опечатка в версии).
func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableError — сетевые сбои, которые имеет смысл повторять.
func retryableError(err error) bool {
	if err == nil {
		return false
	}
	// Отменённый или истёкший контекст — решение вызывающего, а не неполадка:
	// повторять его значит игнорировать отмену.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	// Разрыв соединения приходит обёрнутым в url.Error без net.Error внутри.
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

// serviceOf — имя внешней системы для метрик и предохранителя. Хост, а не
// полный адрес: предохранитель размыкается по реестру целиком, а не по
// отдельному пути в нём.
func serviceOf(u *url.URL) string {
	if u == nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}

// SetClockForTest подменяет часы и ожидание.
//
// Экспортировано ради тестов из внешнего пакета (registry_test): проверять
// паузы и сроки настоящим временем значит либо спать в тесте секундами, либо
// не проверять их вовсе. В бою не вызывается.
func (d *ResilientDoer) SetClockForTest(now func() time.Time,
	sleep func(context.Context, time.Duration) error) {
	d.now, d.sleep = now, sleep
}
