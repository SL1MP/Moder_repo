package registry_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"moderation/internal/registry"
)

// flakyDoer — реестр с заранее заданной последовательностью ответов.
type flakyDoer struct {
	responses []flakyResponse
	calls     int
}

type flakyResponse struct {
	status int
	err    error
	body   string
	header http.Header
}

func (f *flakyDoer) Do(*http.Request) (*http.Response, error) {
	i := f.calls
	f.calls++
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	r := f.responses[i]
	if r.err != nil {
		return nil, r.err
	}
	body := r.body
	if body == "" {
		body = "{}"
	}
	return &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     r.header,
	}, nil
}

// newResilient — обёртка с мгновенными паузами: проверяем логику повторов, а
// не умение ждать.
func newResilient(next registry.Doer, retry registry.RetryPolicy, breaker registry.BreakerPolicy,
	now *time.Time) *registry.ResilientDoer {
	d := registry.NewResilientDoer(next, retry, breaker)
	d.SetClockForTest(func() time.Time { return *now },
		func(context.Context, time.Duration) error { return nil })
	return d
}

func request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, "https://pypi.test/pypi/requests/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestRetryRecoversFromTransientFailure — реестр моргнул, повтор помог.
//
// Именно ради этого случая повторы и заведены: без них весь прогон пакета —
// включая скачивание артефакта и обращение в песочницу — переигрывался бы
// из-за одного 502.
func TestRetryRecoversFromTransientFailure(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{
		{status: http.StatusBadGateway},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	d := newResilient(flaky, registry.DefaultRetryPolicy(), registry.DefaultBreakerPolicy(), &now)

	resp, err := d.Do(request(t))
	if err != nil {
		t.Fatalf("повтор не помог: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("код = %d", resp.StatusCode)
	}
	if flaky.calls != 2 {
		t.Errorf("обращений: %d, ожидалось 2", flaky.calls)
	}
}

func TestRetryAfterIsHonored(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{
		{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"2"}}},
		{status: http.StatusOK},
	}}
	d := registry.NewResilientDoer(flaky, registry.DefaultRetryPolicy(), registry.DefaultBreakerPolicy())
	var waited time.Duration
	d.SetClockForTest(func() time.Time { return now }, func(_ context.Context, delay time.Duration) error {
		waited = delay
		return nil
	})
	resp, err := d.Do(request(t))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if waited != 2*time.Second || flaky.calls != 2 {
		t.Errorf("ожидание = %s, обращений = %d", waited, flaky.calls)
	}
}

func TestLongRetryAfterIsNotRetried(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{{
		status: http.StatusTooManyRequests,
		header: http.Header{"Retry-After": []string{"1800"}},
	}}}
	d := newResilient(flaky, registry.DefaultRetryPolicy(), registry.DefaultBreakerPolicy(), &now)
	resp, err := d.Do(request(t))
	if err != nil {
		t.Fatalf("429 должен вернуться вызывающему без 30-минутного ожидания: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || flaky.calls != 1 {
		t.Errorf("код = %d, обращений = %d", resp.StatusCode, flaky.calls)
	}
}

// TestNotFoundIsNotRetried — 404 повторять нельзя.
//
// «Версии нет» — ответ реестра, а не его недоступность. Повтор втрое
// замедлил бы самый частый случай ошибки пользователя (опечатка в версии) и
// ничего бы не изменил.
func TestNotFoundIsNotRetried(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{{status: http.StatusNotFound}}}
	d := newResilient(flaky, registry.DefaultRetryPolicy(), registry.DefaultBreakerPolicy(), &now)

	resp, err := d.Do(request(t))
	if err != nil {
		t.Fatalf("404 отдан ошибкой: %v", err)
	}
	resp.Body.Close()
	if flaky.calls != 1 {
		t.Errorf("обращений: %d — 404 повторяться не должен", flaky.calls)
	}
}

// TestCanceledContextIsNotRetried — отмена это решение вызывающего, а не
// неполадка реестра.
func TestCanceledContextIsNotRetried(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{{err: context.Canceled}}}
	d := newResilient(flaky, registry.DefaultRetryPolicy(), registry.DefaultBreakerPolicy(), &now)

	if _, err := d.Do(request(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("ошибка = %v, ожидалась отмена", err)
	}
	if flaky.calls != 1 {
		t.Errorf("обращений: %d — отменённый запрос повторяться не должен", flaky.calls)
	}
}

// netFail — сетевая ошибка, как её отдаёт http.Client.
func netFail() error {
	return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
}

// TestBreakerOpensAfterThreshold — лежащий реестр перестаёт опрашиваться.
//
// Без предохранителя упавший реестр превращает разбор очереди в
// последовательное ожидание таймаута на каждом пакете, и сервис выглядит
// зависшим, хотя работает ровно как написано.
func TestBreakerOpensAfterThreshold(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{{err: netFail()}}}
	// Одна попытка на запрос, чтобы считать неудачи, а не попытки.
	retry := registry.RetryPolicy{Attempts: 1}
	breaker := registry.BreakerPolicy{FailureThreshold: 3, OpenFor: 30 * time.Second}
	d := newResilient(flaky, retry, breaker, &now)

	for i := 1; i <= 3; i++ {
		if _, err := d.Do(request(t)); err == nil {
			t.Fatalf("запрос %d прошёл, хотя реестр лежит", i)
		}
	}
	callsBefore := flaky.calls

	_, err := d.Do(request(t))
	if !errors.Is(err, registry.ErrCircuitOpen) {
		t.Fatalf("ошибка = %v, ожидался разомкнутый предохранитель", err)
	}
	if flaky.calls != callsBefore {
		t.Error("запрос ушёл в реестр при разомкнутом предохранителе")
	}
	// Сообщение обязано отличать «реестр недоступен» от «версии нет»: шаг
	// конвейера показывает его человеку.
	if !strings.Contains(err.Error(), "pypi.test") {
		t.Errorf("в сообщении нет имени реестра: %v", err)
	}
}

// TestBreakerLetsOneProbeThrough — по истечении срока пускается ОДНА проба.
//
// Пустить все сразу значило бы обрушить на едва поднявшийся реестр всю
// накопленную очередь.
func TestBreakerLetsOneProbeThrough(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{{err: netFail()}}}
	retry := registry.RetryPolicy{Attempts: 1}
	breaker := registry.BreakerPolicy{FailureThreshold: 2, OpenFor: 30 * time.Second}
	d := newResilient(flaky, retry, breaker, &now)

	d.Do(request(t))
	d.Do(request(t))
	if _, err := d.Do(request(t)); !errors.Is(err, registry.ErrCircuitOpen) {
		t.Fatal("предохранитель не разомкнулся")
	}

	// Срок вышел — одна проба уходит, и она снова неудачна.
	now = now.Add(31 * time.Second)
	before := flaky.calls
	if _, err := d.Do(request(t)); errors.Is(err, registry.ErrCircuitOpen) {
		t.Fatal("пробная попытка не пущена после истечения срока")
	}
	if flaky.calls != before+1 {
		t.Errorf("обращений к реестру: %d, ожидалась одна проба", flaky.calls-before)
	}
	// Проба не удалась — снова разомкнуто, и отсчёт пошёл заново.
	if _, err := d.Do(request(t)); !errors.Is(err, registry.ErrCircuitOpen) {
		t.Error("после неудачной пробы предохранитель не разомкнулся заново")
	}
}

// TestBreakerClosesAfterSuccess — реестр поднялся, обращения возобновились.
func TestBreakerClosesAfterSuccess(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{
		{err: netFail()}, {err: netFail()},
		{status: http.StatusOK},
	}}
	retry := registry.RetryPolicy{Attempts: 1}
	breaker := registry.BreakerPolicy{FailureThreshold: 2, OpenFor: 10 * time.Second}
	d := newResilient(flaky, retry, breaker, &now)

	d.Do(request(t))
	d.Do(request(t))
	now = now.Add(11 * time.Second)

	resp, err := d.Do(request(t))
	if err != nil {
		t.Fatalf("пробная попытка: %v", err)
	}
	resp.Body.Close()

	// Предохранитель замкнут: следующий запрос уходит без ожидания срока.
	resp, err = d.Do(request(t))
	if err != nil {
		t.Fatalf("после успешной пробы предохранитель не замкнулся: %v", err)
	}
	resp.Body.Close()
}

// TestBreakerIsPerRegistry — упавший pypi не должен закрывать npm.
func TestBreakerIsPerRegistry(t *testing.T) {
	now := time.Now()
	flaky := &flakyDoer{responses: []flakyResponse{{err: netFail()}}}
	retry := registry.RetryPolicy{Attempts: 1}
	breaker := registry.BreakerPolicy{FailureThreshold: 2, OpenFor: time.Minute}
	d := newResilient(flaky, retry, breaker, &now)

	d.Do(request(t))
	d.Do(request(t))
	if _, err := d.Do(request(t)); !errors.Is(err, registry.ErrCircuitOpen) {
		t.Fatal("предохранитель pypi не разомкнулся")
	}

	other, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, "https://npm.test/lodash", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Do(other); errors.Is(err, registry.ErrCircuitOpen) {
		t.Error("упавший pypi разомкнул предохранитель и для npm")
	}
}

// TestRetryBodyIsClosed — тело неудачного ответа закрывается.
//
// Иначе подключение не возвращается в пул, и повторы исчерпают его за
// несколько пакетов: снаружи это выглядит как зависший конвейер.
func TestRetryBodyIsClosed(t *testing.T) {
	now := time.Now()
	tracker := &closeTracker{}
	d := newResilient(tracker, registry.RetryPolicy{Attempts: 3},
		registry.DefaultBreakerPolicy(), &now)

	resp, err := d.Do(request(t))
	if err == nil {
		resp.Body.Close()
	}
	if tracker.opened != tracker.closed {
		t.Errorf("открыто тел: %d, закрыто: %d — подключения утекают",
			tracker.opened, tracker.closed)
	}
}

type closeTracker struct{ opened, closed int }

func (c *closeTracker) Do(*http.Request) (*http.Response, error) {
	c.opened++
	return &http.Response{
		StatusCode: http.StatusBadGateway,
		Body:       readCloser{Reader: strings.NewReader("{}"), onClose: func() { c.closed++ }},
		Header:     http.Header{},
	}, nil
}

type readCloser struct {
	io.Reader
	onClose func()
}

func (r readCloser) Close() error {
	r.onClose()
	return nil
}
