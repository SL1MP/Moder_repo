package main

import (
	"testing"

	"moderation/migrations"
)

func fakeMigrations(versions ...string) []migrations.Migration {
	out := make([]migrations.Migration, 0, len(versions))
	for _, v := range versions {
		out = append(out, migrations.Migration{Version: v, Name: "тест-" + v})
	}
	return out
}

// versionsUpTo отбирает миграции по указанную включительно.
//
// Проверяется не «цикл работает», а граница: отметка ЛИШНЕЙ миграции хуже
// ошибки при отметке. Отмеченная, но не выполненная миграция не будет
// применена никогда — сервис будет считать её накатанной, а в схеме её нет, и
// проявится это не сейчас, а на первом обращении к недостающему столбцу.
func TestVersionsUpToStopsAtTarget(t *testing.T) {
	all := fakeMigrations("0001", "0002", "0010", "0011", "0012", "0013")

	cases := []struct {
		target string
		want   []string
		known  bool
	}{
		{"0012", []string{"0001", "0002", "0010", "0011", "0012"}, true},
		{"0001", []string{"0001"}, true},
		{"0013", []string{"0001", "0002", "0010", "0011", "0012", "0013"}, true},
		// Опечатка в версии не должна молча отметить ничего (или всё):
		// и то и другое оставляет учёт расходящимся со схемой.
		{"0099", nil, false},
		{"12", nil, false},
		{"", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			got, known := versionsUpTo(all, tc.target)
			if known != tc.known {
				t.Fatalf("известность версии %q: %v, ожидалось %v", tc.target, known, tc.known)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("отобрано %d миграций, ожидалось %d: %v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Version != tc.want[i] {
					t.Errorf("позиция %d: %s, ожидалось %s", i, got[i].Version, tc.want[i])
				}
			}
		})
	}
}

// Порядок в наборе — источник правды, а не сортировка на месте: набор читается
// из embed.FS уже упорядоченным, и пересортировка здесь спрятала бы поломку
// чтения набора.
func TestVersionsUpToKeepsSetOrder(t *testing.T) {
	all := fakeMigrations("0001", "0002", "0003")
	got, ok := versionsUpTo(all, "0002")
	if !ok || len(got) != 2 {
		t.Fatalf("отобрано %v, ожидались первые две", got)
	}
	if got[0].Version != "0001" || got[1].Version != "0002" {
		t.Fatalf("порядок нарушен: %v", got)
	}
	if got[0].Name != "тест-0001" {
		t.Errorf("имя миграции потеряно: %q", got[0].Name)
	}
}

// migrationVersionOf достаёт номер из подсказки сверки схемы.
//
// Подсказка написана для человека и называет оба набора миграций
// ("…/0014_package_managers (или alembic 0009)"). Взять из неё не тот номер
// значит посоветовать не ту версию для --baseline — а отметить лишнюю
// миграцию хуже, чем ошибиться в меньшую сторону: отмеченная, но не
// выполненная не применится никогда.
func TestMigrationVersionOf(t *testing.T) {
	cases := map[string]string{
		"backend-go/migrations/0014_package_managers":                     "0014",
		"backend-go/migrations/0012_dependency_tree (или alembic 0007)":   "0012",
		"backend-go/migrations/0002_security_override_on_package_version": "0002",
		// Номер альбемика в хвосте не должен побеждать номер go-набора.
		"backend-go/migrations/0003_code_findings (или alembic 0003)": "0003",
		// Обобщённая подсказка номера не несёт — советовать нечего.
		"пропущенные миграции из backend-go/migrations (или alembic)": "",
		"":                        "",
		"migrations/без-номера_x": "",
	}
	for hint, want := range cases {
		if got := migrationVersionOf(hint); got != want {
			t.Errorf("migrationVersionOf(%q) = %q, ожидалось %q", hint, got, want)
		}
	}
}
