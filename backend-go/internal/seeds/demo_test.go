package seeds

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/domain"
)

// dropDemoData убирает за демо-тестом.
//
// Обязателен, а не желателен: демо-данные названы настоящими именами пакетов
// (requests 2.31.0 и далее) — в этом их смысл на стенде, — и ровно эти же
// имена служат фикстурами другим тестам. База между прогонами не
// пересоздаётся, поэтому оставленный после себя одобренный requests ломает
// TestHappyPath_PyPI_AllStepsPass и разбор poetry.lock на СЛЕДУЮЩЕМ запуске —
// в том же запуске они успевают отработать раньше по алфавиту, и падение
// выглядит как случайное.
//
// Строки пакетов не удаляются, только возвращается их состояние: package и
// package_version общие с другими тестами, и удаление унесло бы их заявки.
func dropDemoData(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("MODERATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		return
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("уборка демо-данных, подключение: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx,
		`DELETE FROM moderation_request WHERE reason = $1`, demoRequestReason); err != nil {
		t.Fatalf("уборка демо-заявки: %v", err)
	}
	names := make([]string, 0, len(demoApproved)+1)
	for _, d := range demoApproved {
		names = append(names, d.Name)
	}
	names = append(names, "httpx")
	if _, err := pool.Exec(ctx, `
		UPDATE package_version SET status = 'new', approved_at = NULL,
		       quarantine_until = NULL, published_at = NULL, max_vuln_score = NULL,
		       license_spdx = NULL, license_source = NULL
		WHERE package_id IN (SELECT id FROM package WHERE name = ANY($1))`,
		names); err != nil {
		t.Fatalf("сброс демо-версий: %v", err)
	}
}

// TestSeedDemoDataIsIdempotent: повторный bootstrap --demo не плодит вторую
// демо-заявку.
//
// Проверяется именно это, потому что bootstrap запускают повторно после
// каждой правки конфигурации стенда, и две одинаковые заявки в списке
// выглядят как сбой сервиса, а не как результат двух запусков команды.
func TestSeedDemoDataIsIdempotent(t *testing.T) {
	s, r, cleanup := mustService(t, "")
	defer cleanup()
	t.Cleanup(func() { dropDemoData(t) })
	ctx := context.Background()

	if _, err := s.SeedDemoData(ctx, ""); err != nil {
		t.Fatalf("первый проход: %v", err)
	}
	second, err := s.SeedDemoData(ctx, "")
	if err != nil {
		t.Fatalf("второй проход: %v", err)
	}
	if second.Requests != 0 {
		t.Errorf("второй проход завёл %d заявок, ожидалось 0", second.Requests)
	}
	if second.Approved != 0 {
		t.Errorf("второй проход одобрил %d пакетов повторно, ожидалось 0", second.Approved)
	}

	request, err := r.FindRequestByReason(ctx, demoRequestReason)
	if err != nil {
		t.Fatalf("поиск демо-заявки: %v", err)
	}
	if request == nil {
		t.Fatal("демо-заявка не найдена после двух проходов")
	}
}

// TestSeedDemoDataStopsAtQuarantine: демо-заявка показывает конвейер целиком —
// пройденные шаги, остановивший шаг и причину ожидания.
//
// Смысл демо-данных ровно в этом: на пустом сервисе не видно, работает он или
// молчит. Заявка без шагов или без причины блокировки не отвечает на этот
// вопрос и стенд не объясняет.
func TestSeedDemoDataStopsAtQuarantine(t *testing.T) {
	s, r, cleanup := mustService(t, "")
	defer cleanup()
	t.Cleanup(func() { dropDemoData(t) })
	ctx := context.Background()

	if _, err := s.SeedDemoData(ctx, ""); err != nil {
		t.Fatalf("демо-данные: %v", err)
	}
	request, err := r.FindRequestByReason(ctx, demoRequestReason)
	if err != nil || request == nil {
		t.Fatalf("демо-заявка не найдена: %v", err)
	}
	if request.Status != "quarantined" {
		t.Errorf("статус заявки %q, ожидался quarantined", request.Status)
	}

	items, err := r.ListItemsByRequest(ctx, request.ID)
	if err != nil {
		t.Fatalf("чтение пакетов заявки: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("в демо-заявке %d пакетов, ожидался 1", len(items))
	}
	item := items[0]
	if item.BlockedReason == nil || *item.BlockedReason == "" {
		t.Error("у остановленного пакета нет причины блокировки")
	}
	if item.CurrentStep == nil || *item.CurrentStep != "quarantine" {
		t.Errorf("текущий шаг %v, ожидался quarantine", item.CurrentStep)
	}

	steps, err := r.ListStepsByItem(ctx, item.ID)
	if err != nil {
		t.Fatalf("чтение шагов: %v", err)
	}
	// Шагов ровно столько, сколько в действующем конвейере: снятые шаги
	// (banner_scan, sast_scan) в новых заявках появляться не должны.
	if len(steps) != len(domain.StepCodes) {
		t.Fatalf("шагов %d, ожидалось %d", len(steps), len(domain.StepCodes))
	}
	byCode := map[string]string{}
	for _, step := range steps {
		byCode[step.StepCode] = step.Result
	}
	for _, retired := range domain.RetiredStepCodes {
		if _, ok := byCode[retired]; ok {
			t.Errorf("в демо-заявке есть снятый шаг %s", retired)
		}
	}
	if byCode["quarantine"] != "warn" {
		t.Errorf("шаг карантина: результат %q, ожидался warn", byCode["quarantine"])
	}
	if byCode["publish"] != "skipped" {
		t.Errorf("шаг публикации: результат %q, ожидался skipped", byCode["publish"])
	}
}

// TestSeedDemoUsersKeepPasswordOnSecondRun: повторный bootstrap без пароля не
// отбирает вход у того, кто уже им пользуется.
func TestSeedDemoUsersKeepPasswordOnSecondRun(t *testing.T) {
	s, _, cleanup := mustService(t, "")
	defer cleanup()
	ctx := context.Background()

	const hash = "$2a$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR"
	if _, err := s.SeedDemoUsers(ctx, hash); err != nil {
		t.Fatalf("первый проход: %v", err)
	}
	users, err := s.SeedDemoUsers(ctx, "")
	if err != nil {
		t.Fatalf("второй проход: %v", err)
	}
	for _, u := range users {
		if u.PasswordHash == nil || *u.PasswordHash != hash {
			t.Errorf("учётка %s потеряла пароль на повторном проходе: %v", u.Username, u.PasswordHash)
		}
	}
}
