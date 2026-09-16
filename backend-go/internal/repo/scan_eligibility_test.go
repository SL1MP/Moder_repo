package repo

import (
	"strings"
	"testing"
)

// Диагностика отвечает на вопрос «почему по пакету нет отчёта». Формулировки
// проверяются наравне с решением: невнятный ответ здесь означает, что
// разбирательство всё равно пойдёт через чтение исходников, ради чего команду
// и заводили.
func TestScanEligibilityReasons(t *testing.T) {
	cases := []struct {
		name     string
		in       ScanEligibility
		eligible bool
		contains string
	}{
		{
			name:     "берём",
			in:       ScanEligibility{Exists: true, DownloadResult: "pass"},
			eligible: true,
			contains: "берём",
		},
		{
			name:     "нет такого пакета",
			in:       ScanEligibility{},
			contains: "нет",
		},
		{
			name:     "отчёты уже есть",
			in:       ScanEligibility{Exists: true, DownloadResult: "pass", Reports: []string{"banner_scan", "sast_scan"}},
			contains: "banner_scan, sast_scan",
		},
		{
			name:     "скачивания ещё не было",
			in:       ScanEligibility{Exists: true},
			contains: "конвейер до него не дошёл",
		},
		{
			name:     "скачивание не прошло",
			in:       ScanEligibility{Exists: true, DownloadResult: "fail"},
			contains: "fail",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Eligible(); got != tc.eligible {
				t.Fatalf("Eligible() = %v, ожидалось %v", got, tc.eligible)
			}
			if reason := tc.in.Reason(); !strings.Contains(reason, tc.contains) {
				t.Fatalf("объяснение %q не содержит %q", reason, tc.contains)
			}
		})
	}
}

// Та же диагностика на живой базе: выборка наблюдателя и объяснение обязаны
// сходиться. Разойдись они — команда уверенно врала бы.
func TestScanEligibilityMatchesWatcherQuery(t *testing.T) {
	r, closePool := mustPool(t)
	defer closePool()
	ctx := t.Context()

	items, err := r.ItemsAwaitingScan(ctx, 5)
	if err != nil {
		t.Fatalf("выборка наблюдателя: %v", err)
	}
	for _, id := range items {
		e, err := r.ScanEligibilityOf(ctx, id)
		if err != nil {
			t.Fatalf("диагностика пакета #%d: %v", id, err)
		}
		if !e.Eligible() {
			t.Fatalf("пакет #%d попал в выборку наблюдателя, но диагностика говорит «%s»", id, e.Reason())
		}
	}
}
