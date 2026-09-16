package main

import (
	"testing"
	"time"
)

// Пауза перед повтором: пакет, который не сканируется в принципе (артефакт
// удалён из реестра, сеть до реестра закрыта), не должен занимать место в
// пачке на каждом тике. Первая повторная попытка остаётся быстрой — сеть
// могла просто моргнуть.
func TestRetryAfterGrows(t *testing.T) {
	w := &watcher{interval: time.Minute}

	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
	}
	for _, tc := range cases {
		if got := w.retryAfter(tc.attempt); got != tc.want {
			t.Errorf("попытка %d: пауза %s, ожидалась %s", tc.attempt, got, tc.want)
		}
	}

	// Потолок: иначе после суток простоя пакет перестал бы проверяться вовсе.
	for _, attempt := range []int{7, 20, 1000} {
		if got := w.retryAfter(attempt); got != time.Hour {
			t.Errorf("попытка %d: пауза %s, ожидался потолок в час", attempt, got)
		}
	}
}

// Наблюдатель с редким интервалом не должен ждать меньше самого интервала:
// иначе повтор случится раньше, чем следующий проход, и пауза ничего не даст.
func TestRetryAfterNotShorterThanInterval(t *testing.T) {
	w := &watcher{interval: 10 * time.Minute}
	if got := w.retryAfter(1); got != 10*time.Minute {
		t.Fatalf("первая пауза %s, ожидался интервал наблюдателя", got)
	}
	if got := w.retryAfter(3); got != 40*time.Minute {
		t.Fatalf("третья пауза %s, ожидалось 40m", got)
	}
}
