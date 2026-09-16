package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"moderation/internal/api"
	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/repo"
)

// Очереди, обсуждения и уведомления — на настоящем Postgres: их поведение это
// и есть SQL (отбор по шагам, права, счётчики), а на моке проверялось бы
// только то, что мок настроен так же, как написан код.

type socialFixture struct {
	router    http.Handler
	repo      *repo.Repo
	verifier  *auth.Verifier
	requestID int64
	itemID    int64
	versionID int64
	author    *domain.User
	outsider  *domain.User
}

func newSocialFixture(t *testing.T, licenseStep, securityStep string, itemStatus string) *socialFixture {
	t.Helper()
	r, cleanup := mustRepo(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	slug := fmt.Sprintf("%s-%d", testSlug(t), time.Now().UnixNano())

	author, err := r.GetOrCreateUser(ctx, "автор-"+slug, "Автор Заявки")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := r.GetOrCreateUser(ctx, "чужой-"+slug, "Чужой Разработчик")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := r.GetOrCreatePackage(ctx, "npm", "soc-"+slug, "Soc-"+slug)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "1.2.3", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: author.ID, Manager: "npm", Status: "awaiting_legal", Source: "ui", Warnings: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	waiting := time.Now().UTC().Add(-3 * time.Hour)
	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req.ID, PackageVersionID: ver.ID,
		RequestedName: pkg.DisplayName, RequestedVersion: "1.2.3",
		DependencyKind: "direct", Status: itemStatus,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateRequestItemStatus(ctx, item.ID, itemStatus, nil, nil, nil, &waiting); err != nil {
		t.Fatal(err)
	}
	for code, result := range map[string]string{"license": licenseStep, "vuln_scan": securityStep} {
		if result == "" {
			continue
		}
		if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
			RequestItemID: item.ID, StepCode: code, StepOrder: domain.StepOrder[code],
			Result: result,
		}); err != nil {
			t.Fatal(err)
		}
	}

	cfg := socialConfig(t)
	verifier := auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil)
	a := &api.Auth{Verifier: verifier, Repo: r}

	return &socialFixture{
		router: api.NewRouter(nil, api.Options{
			Auth:          &api.AuthHandler{Auth: a, Cfg: cfg},
			Queues:        &api.QueuesHandler{Repo: r},
			Comments:      &api.CommentsHandler{Repo: r, Cfg: cfg},
			Notifications: &api.NotificationsHandler{Repo: r},
		}),
		repo: r, verifier: verifier, requestID: req.ID, itemID: item.ID, versionID: ver.ID,
		author: author, outsider: outsider,
	}
}

func socialConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"DATABASE_URL":                "postgres://не-используется",
			"LOCAL_AUTH_ENABLED":          "true",
			"LOCAL_AUTH_SECRET":           "секрет-соц-тестов",
			"COMMENT_EDIT_WINDOW_MINUTES": "15",
		}[k]
	})
	if err != nil {
		t.Fatalf("конфигурация теста невалидна: %v", err)
	}
	return cfg
}

func (f *socialFixture) do(t *testing.T, user *domain.User, roles []string, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	acting := *user
	acting.Roles = roles
	token, _, err := f.verifier.IssueLocalToken(&acting)
	if err != nil {
		t.Fatalf("выпуск токена: %v", err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------- очереди

// Пакет, у которого лицензия ждёт юриста, а уязвимости — DevSecOps, обязан
// попасть В ОБЕ очереди. Статус у пакета один (более блокирующий), и отбор
// только по нему спрятал бы пакет от юриста совсем.
func TestQueuesFindItemByOpenStepNotOnlyStatus(t *testing.T) {
	f := newSocialFixture(t, "warn", "warn", "awaiting_security")

	legal := decodeArray(t, f.do(t, f.outsider, []string{"legal"}, http.MethodGet, "/api/v1/queue/legal", ""))
	if !containsQueueItem(legal, f.itemID) {
		t.Error("пакет с непогашенным шагом лицензии должен быть в очереди юристов, " +
			"хотя его статус — awaiting_security")
	}
	security := decodeArray(t, f.do(t, f.outsider, []string{"devsecops"}, http.MethodGet, "/api/v1/queue/security", ""))
	if !containsQueueItem(security, f.itemID) {
		t.Error("пакет должен быть и в очереди DevSecOps")
	}
}

// Пакет с окончательным вердиктом не нужен ни в одной очереди, даже если шаг
// остался в warn.
func TestQueuesSkipFinishedItems(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "approved")
	legal := decodeArray(t, f.do(t, f.outsider, []string{"legal"}, http.MethodGet, "/api/v1/queue/legal", ""))
	if containsQueueItem(legal, f.itemID) {
		t.Fatal("одобренный пакет не должен висеть в очереди юристов")
	}
}

func TestQueueItemShape(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	items := decodeArray(t, f.do(t, f.outsider, []string{"legal"}, http.MethodGet, "/api/v1/queue/legal", ""))
	row := queueItem(t, items, f.itemID)

	for _, field := range []string{
		"item_id", "request_id", "manager", "name", "version", "status", "status_title",
		"current_step", "blocked_reason", "waiting_since", "waiting_hours", "author",
		"license_spdx", "max_vuln_score", "license_claim_id",
	} {
		if _, ok := row[field]; !ok {
			t.Errorf("в ответе нет поля %q", field)
		}
	}
	// Время ожидания — то, по чему юрист сортирует работу; оно обязано
	// считаться, а не приходить пустым.
	hours, ok := row["waiting_hours"].(float64)
	if !ok || hours < 2.5 || hours > 3.5 {
		t.Fatalf("waiting_hours = %v, ожидалось около 3", row["waiting_hours"])
	}
	if row["author"] != f.author.Username {
		t.Errorf("автор: %v", row["author"])
	}
}

// Очередь чужой роли открываться не должна: это рабочий список другой
// команды, и разработчику там делать нечего.
func TestQueueRoleGuard(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	cases := []struct {
		path, role string
		status     int
	}{
		{"/api/v1/queue/legal", "legal", http.StatusOK},
		{"/api/v1/queue/legal", "devsecops", http.StatusForbidden},
		{"/api/v1/queue/legal", "developer", http.StatusForbidden},
		{"/api/v1/queue/legal", "admin", http.StatusOK},
		{"/api/v1/queue/security", "devsecops", http.StatusOK},
		{"/api/v1/queue/security", "legal", http.StatusForbidden},
		{"/api/v1/queue/security", "admin", http.StatusOK},
	}
	for _, tc := range cases {
		rec := f.do(t, f.outsider, []string{tc.role}, http.MethodGet, tc.path, "")
		if rec.Code != tc.status {
			t.Errorf("%s под ролью %s: код %d, ожидался %d", tc.path, tc.role, rec.Code, tc.status)
		}
	}
}

// Счётчики очередей приходят только тем, у кого есть роль: разработчику знать
// размер очереди юристов незачем.
func TestQueueCountersScopedByRole(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")

	dev := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, "/api/v1/queue/counters", ""))
	if _, ok := dev["legal"]; ok {
		t.Error("разработчику счётчик очереди юристов не положен")
	}
	if _, ok := dev["unread_notifications"]; !ok {
		t.Error("счётчик своих уведомлений положен всем")
	}

	legal := decodeObject(t, f.do(t, f.outsider, []string{"legal"}, http.MethodGet, "/api/v1/queue/counters", ""))
	if _, ok := legal["legal"]; !ok {
		t.Error("юристу счётчик его очереди положен")
	}
	if _, ok := legal["security"]; ok {
		t.Error("юристу счётчик очереди DevSecOps не положен")
	}
}

// ---------------------------------------------------------------- обсуждения

func TestCommentLifecycle(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)

	rec := f.do(t, f.author, []string{"developer"}, http.MethodPost, path,
		`{"body":"  Нужен для сборки, приложил ссылку на лицензию.  "}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("добавление: код %d, тело %s", rec.Code, rec.Body.String())
	}
	created := decodeObject(t, rec)
	if created["body"] != "Нужен для сборки, приложил ссылку на лицензию." {
		t.Fatalf("текст должен обрезаться по краям: %q", created["body"])
	}
	if created["is_edited"] != false || created["deleted"] != false || created["can_edit"] != true {
		t.Fatalf("флаги нового сообщения: %v", created)
	}
	commentID := int64(created["id"].(float64))

	list := decodeArray(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, path, ""))
	if len(list) != 1 {
		t.Fatalf("в ветке %d сообщений", len(list))
	}

	// Правка внутри окна не помечается «изменено»: это опечатка, а не
	// переписывание истории.
	edit := fmt.Sprintf("/api/v1/comments/%d", commentID)
	edited := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodPatch, edit,
		`{"body":"Поправил опечатку."}`))
	if edited["is_edited"] != false {
		t.Errorf("правка внутри окна не помечается: %v", edited["is_edited"])
	}
	if edited["body"] != "Поправил опечатку." {
		t.Errorf("текст не изменился: %v", edited["body"])
	}

	deleted := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodDelete, edit, ""))
	if deleted["deleted"] != true || deleted["body"] != "Сообщение удалено" {
		t.Fatalf("удаление: %v", deleted)
	}
	if deleted["can_edit"] != false {
		t.Error("удалённое сообщение править нельзя")
	}
	// Повторное удаление — понятная ошибка, а не пятисотка.
	again := f.do(t, f.author, []string{"developer"}, http.MethodDelete, edit, "")
	if again.Code != http.StatusUnprocessableEntity {
		t.Errorf("повторное удаление: код %d", again.Code)
	}
}

// Правка позже окна помечается «изменено»: собеседники уже прочитали текст.
func TestCommentEditedOutsideWindowIsMarked(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)
	created := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodPost, path,
		`{"body":"исходный текст"}`))
	commentID := int64(created["id"].(float64))

	// Сдвигаем время вперёд, а не спим: окно правки — 15 минут.
	late := &api.CommentsHandler{Repo: f.repo, Cfg: socialConfig(t),
		Now: func() time.Time { return time.Now().UTC().Add(time.Hour) }}
	cfg := socialConfig(t)
	router := api.NewRouter(nil, api.Options{
		Auth:     &api.AuthHandler{Auth: &api.Auth{Verifier: f.verifier, Repo: f.repo}, Cfg: cfg},
		Comments: late,
	})
	token, _, _ := f.verifier.IssueLocalToken(&domain.User{
		ID: f.author.ID, Username: f.author.Username, Roles: []string{"developer"}, IsActive: true})
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/comments/%d", commentID),
		strings.NewReader(`{"body":"переписал позже"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	edited := decodeObject(t, rec)
	if edited["is_edited"] != true {
		t.Fatalf("правка позже окна обязана помечаться: %v", edited)
	}
	if edited["edited_at"] == nil {
		t.Error("время правки должно проставляться")
	}
}

func TestCommentAccess(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)

	if rec := f.do(t, f.outsider, []string{"developer"}, http.MethodGet, path, ""); rec.Code != http.StatusForbidden {
		t.Errorf("чужой разработчик не должен читать обсуждение: %d", rec.Code)
	}
	for _, role := range []string{"devsecops", "legal", "admin"} {
		if rec := f.do(t, f.outsider, []string{role}, http.MethodGet, path, ""); rec.Code != http.StatusOK {
			t.Errorf("роль %s должна видеть обсуждение: %d", role, rec.Code)
		}
	}
}

// Чужое сообщение правит только администратор.
func TestCommentEditOwnership(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)
	created := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodPost, path,
		`{"body":"моё сообщение"}`))
	edit := fmt.Sprintf("/api/v1/comments/%d", int64(created["id"].(float64)))

	if rec := f.do(t, f.outsider, []string{"devsecops"}, http.MethodPatch, edit, `{"body":"чужая правка"}`); rec.Code != http.StatusForbidden {
		t.Errorf("DevSecOps не правит чужие сообщения: %d", rec.Code)
	}
	if rec := f.do(t, f.outsider, []string{"admin"}, http.MethodPatch, edit, `{"body":"правка админа"}`); rec.Code != http.StatusOK {
		t.Errorf("администратор правит любые: %d", rec.Code)
	}
}

func TestCommentValidation(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)
	for _, body := range []string{`{"body":""}`, `{"body":"   "}`, `не json`, `{}`} {
		if rec := f.do(t, f.author, []string{"developer"}, http.MethodPost, path, body); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("тело %q: код %d, ожидался 422", body, rec.Code)
		}
	}
	// Ветка чужого пакета — не 500, а понятный 404.
	rec := f.do(t, f.author, []string{"developer"}, http.MethodPost, path,
		`{"body":"в чужую ветку","request_item_id":999999999}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("чужой пакет заявки: код %d, ожидался 404", rec.Code)
	}
}

// Ветка одного пакета фильтруется отдельно: в заявке их до двухсот, и общая
// лента была бы нечитаемой.
func TestCommentsFilteredByItem(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)
	f.do(t, f.author, []string{"developer"}, http.MethodPost, path, `{"body":"по заявке целиком"}`)
	f.do(t, f.author, []string{"developer"}, http.MethodPost, path,
		fmt.Sprintf(`{"body":"по пакету","request_item_id":%d}`, f.itemID))

	all := decodeArray(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, path, ""))
	if len(all) != 2 {
		t.Fatalf("в ветке заявки должно быть 2 сообщения, получено %d", len(all))
	}
	byItem := decodeArray(t, f.do(t, f.author, []string{"developer"}, http.MethodGet,
		fmt.Sprintf("%s?request_item_id=%d", path, f.itemID), ""))
	if len(byItem) != 1 {
		t.Fatalf("в ветке пакета должно быть 1 сообщение, получено %d", len(byItem))
	}
}

// ---------------------------------------------------------------- уведомления

// Сообщение в обсуждении уведомляет автора заявки и упомянутых, но не самого
// автора сообщения.
func TestCommentNotifiesParticipants(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)

	body := fmt.Sprintf(`{"body":"@%s посмотри пожалуйста"}`, f.outsider.Username)
	if rec := f.do(t, f.outsider, []string{"devsecops"}, http.MethodPost, path, body); rec.Code != http.StatusOK {
		t.Fatalf("добавление: %d %s", rec.Code, rec.Body.String())
	}

	// Автору заявки уведомление пришло.
	authorFeed := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, "/api/v1/notifications", ""))
	if authorFeed["unread"] == float64(0) {
		t.Error("автор заявки должен получить уведомление о новом сообщении")
	}

	// А тому, кто сам его написал и сам себя упомянул, — нет.
	selfFeed := decodeObject(t, f.do(t, f.outsider, []string{"devsecops"}, http.MethodGet, "/api/v1/notifications", ""))
	if selfFeed["unread"] != float64(0) {
		t.Errorf("автор сообщения не уведомляется о себе: %v", selfFeed["unread"])
	}
}

func TestNotificationsMarkRead(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)
	f.do(t, f.outsider, []string{"devsecops"}, http.MethodPost, path, `{"body":"первое"}`)
	f.do(t, f.outsider, []string{"devsecops"}, http.MethodPost, path, `{"body":"второе"}`)

	feed := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, "/api/v1/notifications", ""))
	items := feed["items"].([]any)
	if len(items) < 2 {
		t.Fatalf("уведомлений %d, ожидалось минимум 2", len(items))
	}
	first := int64(items[0].(map[string]any)["id"].(float64))

	one := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodPost,
		"/api/v1/notifications/read", fmt.Sprintf(`{"ids":[%d]}`, first)))
	if one["updated"] != float64(1) {
		t.Fatalf("отмечено %v, ожидалось 1", one["updated"])
	}

	all := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodPost,
		"/api/v1/notifications/read", `{"all":true}`))
	if all["updated"] == float64(0) {
		t.Error("остальные должны отметиться")
	}
	after := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, "/api/v1/notifications", ""))
	if after["unread"] != float64(0) {
		t.Fatalf("непрочитанных осталось %v", after["unread"])
	}
}

// Чужой идентификатор в списке не должен помечать прочитанным чужое
// уведомление: фильтр по пользователю стоит в самом запросе.
func TestMarkReadCannotTouchOthers(t *testing.T) {
	f := newSocialFixture(t, "warn", "", "awaiting_legal")
	path := fmt.Sprintf("/api/v1/requests/%d/comments", f.requestID)
	f.do(t, f.outsider, []string{"devsecops"}, http.MethodPost, path, `{"body":"автору заявки"}`)

	feed := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, "/api/v1/notifications", ""))
	items := feed["items"].([]any)
	if len(items) == 0 {
		t.Fatal("уведомление автору не создано")
	}
	foreign := int64(items[0].(map[string]any)["id"].(float64))

	res := decodeObject(t, f.do(t, f.outsider, []string{"devsecops"}, http.MethodPost,
		"/api/v1/notifications/read", fmt.Sprintf(`{"ids":[%d]}`, foreign)))
	if res["updated"] != float64(0) {
		t.Fatalf("чужое уведомление отмечено прочитанным: %v", res["updated"])
	}
	after := decodeObject(t, f.do(t, f.author, []string{"developer"}, http.MethodGet, "/api/v1/notifications", ""))
	if after["unread"] == float64(0) {
		t.Fatal("уведомление автора не должно было пропасть")
	}
}

func containsQueueItem(items []any, itemID int64) bool {
	for _, raw := range items {
		if row, ok := raw.(map[string]any); ok && row["item_id"] == float64(itemID) {
			return true
		}
	}
	return false
}

func queueItem(t *testing.T, items []any, itemID int64) map[string]any {
	t.Helper()
	for _, raw := range items {
		if row, ok := raw.(map[string]any); ok && row["item_id"] == float64(itemID) {
			return row
		}
	}
	t.Fatalf("пакет #%d не найден в очереди", itemID)
	return nil
}
