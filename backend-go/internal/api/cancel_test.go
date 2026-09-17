package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"moderation/internal/domain"
)

// Закрытие заявки автором. Проверяется на настоящем Postgres: вся суть
// маршрута — какие строки он меняет и каких не касается.

// post выполняет POST от имени пользователя с заданными ролями.
func (f *readFixture) post(t *testing.T, user *domain.User, roles []string, path string) *httptest.ResponseRecorder {
	t.Helper()
	acting := *user
	acting.Roles = roles
	token, _, err := f.verifier.IssueLocalToken(&acting)
	if err != nil {
		t.Fatalf("выпуск токена: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f *readFixture) cancelPath() string {
	return "/api/v1/requests/" + strconv.FormatInt(f.requestID, 10) + "/cancel"
}

// hasAudit — есть ли в журнале запись с таким действием по этой заявке.
func hasAudit(t *testing.T, f *readFixture, action string) bool {
	t.Helper()
	var count int
	err := f.repo.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = $1 AND entity_id = $2`,
		action, strconv.FormatInt(f.requestID, 10)).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	return count > 0
}

// TestCancelByAuthor — автор закрывает свою заявку: пакеты больше не нужны.
func TestCancelByAuthor(t *testing.T) {
	f := newReadFixture(t)
	ctx := context.Background()

	rec := f.post(t, f.author, []string{"developer"}, f.cancelPath())
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	if payload["cancelled"] != float64(1) {
		t.Errorf("cancelled = %v, ожидался 1", payload["cancelled"])
	}

	item, err := f.repo.GetRequestItem(ctx, f.itemID)
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "cancelled" {
		t.Errorf("статус пакета = %q, ожидался cancelled", item.Status)
	}
	// Ожидание роли снято: иначе пакет остался бы в очереди юристов как
	// работа, которой уже нет.
	if item.WaitingSince != nil || item.NextAction != nil {
		t.Errorf("пакет всё ещё ждёт: waiting_since=%v next_action=%v",
			item.WaitingSince, item.NextAction)
	}
	req, err := f.repo.GetModerationRequest(ctx, f.requestID)
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != "cancelled" {
		t.Errorf("статус заявки = %q, ожидался cancelled", req.Status)
	}
	// Отказ автора должен быть в журнале: он объясняет, почему заявка не
	// доехала до решения роли.
	if !hasAudit(t, f, "request_cancelled") {
		t.Error("закрытие заявки не попало в журнал")
	}
}

// TestCancelForbiddenForOthers — закрыть заявку может только автор.
//
// DevSecOps и юрист сюда не входят сознательно: у них есть отклонение,
// которое означает решение по существу. Отмена от их имени стёрла бы из
// журнала то, кто на самом деле отказал.
func TestCancelForbiddenForOthers(t *testing.T) {
	f := newReadFixture(t)

	for _, role := range []string{"developer", "devsecops", "legal"} {
		rec := f.post(t, f.outsider, []string{role}, f.cancelPath())
		if rec.Code != http.StatusForbidden {
			t.Errorf("роль %s: код %d, ожидался 403 (тело %s)",
				role, rec.Code, rec.Body.String())
		}
	}
	item, err := f.repo.GetRequestItem(context.Background(), f.itemID)
	if err != nil {
		t.Fatal(err)
	}
	if item.Status == "cancelled" {
		t.Fatal("чужая заявка закрыта")
	}
}

// TestCancelTwiceIsConflict — повторное нажатие кнопки не ошибка сервера и не
// молчаливое «ок»: заявка уже закрыта, и ответ это говорит.
func TestCancelTwiceIsConflict(t *testing.T) {
	f := newReadFixture(t)

	if rec := f.post(t, f.author, []string{"developer"}, f.cancelPath()); rec.Code != http.StatusOK {
		t.Fatalf("первое закрытие: код %d", rec.Code)
	}
	rec := f.post(t, f.author, []string{"developer"}, f.cancelPath())
	if rec.Code != http.StatusConflict {
		t.Fatalf("код %d, ожидался 409 (тело %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "уже закрыта") {
		t.Errorf("тело %s — ответ должен называть причину", rec.Body.String())
	}
}

// TestCancelDoesNotTouchFinishedPackages — отмена не отзывает решение.
// Опубликованный пакет снимает DevSecOps, а не автор задним числом.
func TestCancelDoesNotTouchFinishedPackages(t *testing.T) {
	f := newReadFixture(t)
	ctx := context.Background()

	if _, err := f.repo.Pool().Exec(ctx,
		`UPDATE request_item SET status = 'approved' WHERE id = $1`, f.itemID); err != nil {
		t.Fatal(err)
	}

	rec := f.post(t, f.author, []string{"developer"}, f.cancelPath())
	if rec.Code != http.StatusConflict {
		t.Fatalf("код %d, ожидался 409 (тело %s)", rec.Code, rec.Body.String())
	}
	item, err := f.repo.GetRequestItem(ctx, f.itemID)
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "approved" {
		t.Fatalf("статус пакета = %q — отмена тронула завершённый пакет", item.Status)
	}
}

// TestCancelledItemDropsOutOfRollup — отменённый пакет не тянет заявку в
// «отклонена»: автор сказал, что он не нужен, а не что он запрещён.
func TestCancelledItemDropsOutOfRollup(t *testing.T) {
	f := newReadFixture(t)
	ctx := context.Background()

	// Второй пакет в той же заявке доходит до одобрения.
	second, err := f.repo.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: f.requestID, PackageVersionID: f.versionID,
		RequestedName: "второй", RequestedVersion: "2.31.0",
		DependencyKind: "direct", Status: "approved",
	})
	if err != nil {
		t.Fatal(err)
	}

	if rec := f.post(t, f.author, []string{"developer"}, f.cancelPath()); rec.Code != http.StatusOK {
		t.Fatalf("закрытие: код %d, тело %s", rec.Code, rec.Body.String())
	}

	req, err := f.repo.GetModerationRequest(ctx, f.requestID)
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != "approved" {
		t.Fatalf("статус заявки = %q, ожидался approved: единственный "+
			"незавершённый пакет отменён, остальное одобрено", req.Status)
	}
	item, err := f.repo.GetRequestItem(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "approved" {
		t.Errorf("статус второго пакета = %q — отмена тронула чужой пакет", item.Status)
	}
}

// TestCancelExplainsMissingMigration — база не разрешает статус `cancelled`
// (миграцию не накатили): ответ говорит, что отстала схема, называет
// ограничение и команду, которая покажет недостающие миграции, — вместо
// глухого «Заявка не закрыта».
//
// Тест написан по живому случаю: кнопка отвечала 500, и по ответу понять,
// что дело в развёртывании, а не в заявке, было невозможно.
func TestCancelExplainsMissingMigration(t *testing.T) {
	f := newReadFixture(t)
	ctx := context.Background()

	const dropNew = `ALTER TABLE request_item DROP CONSTRAINT IF EXISTS request_item_status_check`
	// NOT VALID: в общей тестовой базе уже есть строки со статусом
	// `cancelled` от других тестов, и обычное ограничение на них не
	// налезет. Проверку новых записей NOT VALID не отменяет — именно она
	// здесь и нужна.
	const addOld = `ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
		'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
		'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
		'blacklisted', 'failed')) NOT VALID`
	const addNew = `ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
		'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
		'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
		'blacklisted', 'cancelled', 'failed'))`

	if _, err := f.repo.Pool().Exec(ctx, dropNew); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Pool().Exec(ctx, addOld); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := f.repo.Pool().Exec(context.Background(), dropNew); err != nil {
			t.Fatalf("восстановление ограничения: %v", err)
		}
		if _, err := f.repo.Pool().Exec(context.Background(), addNew); err != nil {
			t.Fatalf("восстановление ограничения: %v", err)
		}
	}()

	rec := f.post(t, f.author, []string{"developer"}, f.cancelPath())
	body := rec.Body.String()
	if !strings.Contains(body, "Схема базы не соответствует") {
		t.Fatalf("тело %s — ответ должен называть причину", body)
	}
	if !strings.Contains(body, "request_item_status_check") {
		t.Errorf("тело %s — ответ должен называть ограничение", body)
	}
	if !strings.Contains(body, "schema") {
		t.Errorf("тело %s — ответ должен называть команду сверки схемы", body)
	}
}
