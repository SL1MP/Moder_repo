package api_test

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"moderation/internal/api"
	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/queue"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/requests"
)

// Создание заявки проверяется на настоящем Postgres: половина его работы —
// сверка с базой (что уже одобрено, что запрещено, что заводится впервые) и
// постановка пакетов в очередь.

type createFixture struct {
	router   http.Handler
	repo     *repo.Repo
	queue    *queue.Queue
	verifier *auth.Verifier
	user     *domain.User
	slug     string
}

func newCreateFixture(t *testing.T) *createFixture {
	t.Helper()
	r, cleanup := mustRepo(t)
	t.Cleanup(cleanup)
	slug := fmt.Sprintf("%s-%d", testSlug(t), time.Now().UnixNano())

	user, err := r.GetOrCreateUser(context.Background(), "автор-"+slug, "Автор")
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"DATABASE_URL":             "postgres://не-используется",
			"LOCAL_AUTH_ENABLED":       "true",
			"LOCAL_AUTH_SECRET":        "секрет-создания",
			"ARTIFACT_BASE_URL":        "https://artifactory.example.com",
			"MAX_PACKAGES_PER_REQUEST": "5",
			"MAX_UPLOAD_SIZE_BYTES":    "65536",
		}[k]
	})
	if err != nil {
		t.Fatalf("конфигурация: %v", err)
	}

	reg := registry.New(registry.Config{})
	q := queue.New(r.Pool(), time.Minute)
	verifier := auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil)
	handler := &api.RequestsHandler{
		Repo: r, Registry: reg, Cfg: cfg, Queue: q,
		Requests: &requests.Service{
			Repo: r, Registry: reg,
			Limits: requests.Limits{
				MaxPackages: cfg.MaxPackagesPerRequest, MaxUploadSize: cfg.MaxUploadSizeBytes,
			},
			InstallCommand: func(manager, name, displayName, version, rawVersion string) string {
				plugin, err := reg.Get(manager)
				if err != nil {
					return ""
				}
				return plugin.InstallCommand(registry.Ref{
					Manager: manager, Name: name, DisplayName: displayName,
					Version: version, RawVersion: rawVersion,
				}, cfg.ArtifactBaseURL, cfg.ArtifactRepo(manager))
			},
		},
	}
	return &createFixture{
		router: api.NewRouter(nil, api.Options{
			Auth:     &api.AuthHandler{Auth: &api.Auth{Verifier: verifier, Repo: r}, Cfg: cfg},
			Requests: handler,
		}),
		repo: r, queue: q, verifier: verifier, user: user, slug: slug,
	}
}

func (f *createFixture) post(t *testing.T, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return f.send(t, "application/json", strings.NewReader(body), headers)
}

func (f *createFixture) send(t *testing.T, contentType string, body *strings.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/requests", body)
	req.Header.Set("Content-Type", contentType)
	f.authorize(t, req, headers)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f *createFixture) authorize(t *testing.T, req *http.Request, headers map[string]string) {
	t.Helper()
	acting := *f.user
	acting.Roles = []string{"developer"}
	if role, ok := headers["role"]; ok {
		if role == "" {
			acting.Roles = nil
		} else {
			acting.Roles = []string{role}
		}
		delete(headers, "role")
	}
	token, _, err := f.verifier.IssueLocalToken(&acting)
	if err != nil {
		t.Fatalf("токен: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func TestCreateRequestFromJSON(t *testing.T) {
	f := newCreateFixture(t)
	body := fmt.Sprintf(`{"manager":"pypi","reason":"нужен для сборки",
		"packages":["pkg-%s==1.0.0","other-%s==2.0.0"]}`, f.slug, f.slug)

	rec := f.post(t, body, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	if payload["accepted"] != float64(2) {
		t.Fatalf("принято %v, ожидалось 2", payload["accepted"])
	}
	if payload["status_url"] != fmt.Sprintf("/api/v1/requests/%d", int64(payload["request_id"].(float64))) {
		t.Errorf("status_url: %v", payload["status_url"])
	}

	// Пакеты обязаны оказаться в очереди: без этого заявка создана, а
	// проверка не начнётся никогда.
	items, err := f.repo.ListItemsByRequest(context.Background(), int64(payload["request_id"].(float64)))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("пакетов заявки %d", len(items))
	}
	for _, item := range items {
		if item.Status != "queued" {
			t.Errorf("пакет #%d в статусе %q, ожидался queued", item.ID, item.Status)
		}
	}
}

// Объектная форма записи используется наравне со строковой.
func TestCreateRequestStructuredPackages(t *testing.T) {
	f := newCreateFixture(t)
	body := fmt.Sprintf(`{"manager":"npm","packages":[{"name":"pkg-%s","version":"1.2.3"}]}`, f.slug)
	rec := f.post(t, body, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if decodeObject(t, rec)["accepted"] != float64(1) {
		t.Fatalf("тело: %s", rec.Body.String())
	}
}

// Уже одобренный пакет в заявку не попадает: заводить вторую заявку на то,
// что можно ставить прямо сейчас, — пустая работа для всех ролей.
func TestCreateRequestSkipsApproved(t *testing.T) {
	f := newCreateFixture(t)
	ctx := context.Background()
	pkg, err := f.repo.GetOrCreatePackage(ctx, "pypi", "approved-"+f.slug, "Approved-"+f.slug)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := f.repo.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.UpdatePackageVersionStatus(ctx, ver.ID, "approved", nil); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"manager":"pypi","packages":["approved-%s==1.0.0","new-%s==1.0.0"]}`,
		f.slug, f.slug)
	rec := f.post(t, body, nil)
	payload := decodeObject(t, rec)
	if payload["accepted"] != float64(1) || payload["skipped_already_in_base"] != float64(1) {
		t.Fatalf("сводка: %v", payload)
	}
	for _, raw := range payload["packages"].([]any) {
		p := raw.(map[string]any)
		if p["state"] != "already_in_base" {
			continue
		}
		// Разработчику нужна не отписка «уже есть», а команда установки.
		if cmd, _ := p["install_command"].(string); !strings.Contains(cmd, "pip install") {
			t.Errorf("у одобренного пакета должна быть команда установки: %v", p)
		}
	}
}

func TestCreateRequestInvalidEntries(t *testing.T) {
	f := newCreateFixture(t)
	// Имя валидного пакета — латиницей: PEP 503 разрешает только буквы
	// латинского алфавита, цифры и «-_.».
	body := fmt.Sprintf(`{"manager":"pypi","packages":["ok-%s==1.0.0","без-версии","!!!"]}`, f.slug)
	rec := f.post(t, body, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	if payload["invalid"] != float64(2) || payload["accepted"] != float64(1) {
		t.Fatalf("сводка: %v", payload)
	}
	// Каждая непринятая запись обязана объяснять себя: иначе разработчик
	// видит «2 invalid» и не знает, что чинить.
	for _, raw := range payload["packages"].([]any) {
		p := raw.(map[string]any)
		if p["state"] == "invalid_format" {
			if msg, _ := p["message"].(string); msg == "" {
				t.Errorf("запись без объяснения: %v", p)
			}
			if fmtHint, _ := p["expected_format"].(string); fmtHint == "" {
				t.Errorf("запись без подсказки формата: %v", p)
			}
		}
	}
}

func TestCreateRequestValidation(t *testing.T) {
	f := newCreateFixture(t)
	cases := []struct {
		name, body string
		status     int
	}{
		{"пустое тело", ``, http.StatusUnprocessableEntity},
		{"не json", `не json`, http.StatusUnprocessableEntity},
		{"без менеджера", `{"packages":["a==1.0.0"]}`, http.StatusUnprocessableEntity},
		{"пустой список", `{"manager":"pypi","packages":[]}`, http.StatusUnprocessableEntity},
		{"неизвестный менеджер", `{"manager":"maven","packages":["a:b:1"]}`, http.StatusUnprocessableEntity},
		{"больше предела", `{"manager":"pypi","packages":["a==1","b==1","c==1","d==1","e==1","f==1"]}`,
			http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.post(t, tc.body, nil)
			if rec.Code != tc.status {
				t.Fatalf("код %d, ожидался %d: %s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

// Заявка без единой роли не заводится: это почти всегда незаданный маппинг
// групп, и сообщение обязано вести к причине.
//
// Учётку заводим с пустыми ролями прямо в базе: пустые claims токена роли НЕ
// сбрасывают (сбой маппера групп не должен разжаловать всех разом), поэтому
// «токен без ролей» сам по себе такой случай не воспроизводит.
func TestCreateRequestNeedsRole(t *testing.T) {
	f := newCreateFixture(t)
	ctx := context.Background()
	if _, err := f.repo.Pool().Exec(ctx,
		`UPDATE "user" SET roles = '[]'::jsonb WHERE id = $1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"manager":"pypi","packages":["pkg-%s==1.0.0"]}`, f.slug)
	rec := f.post(t, body, map[string]string{"role": ""})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ROLE_MAPPING_") {
		t.Errorf("сообщение должно указывать на маппинг групп: %s", rec.Body.String())
	}
}

// Повтор с тем же Idempotency-Key не создаёт вторую заявку: перезапуск
// пайплайна CI не должен множить работу ролей.
func TestCreateRequestIdempotency(t *testing.T) {
	f := newCreateFixture(t)
	body := fmt.Sprintf(`{"manager":"pypi","packages":["idem-%s==1.0.0"]}`, f.slug)
	key := map[string]string{"Idempotency-Key": "ключ-" + f.slug}

	first := f.post(t, body, copyHeaders(key))
	if first.Code != http.StatusAccepted {
		t.Fatalf("первая заявка: %d %s", first.Code, first.Body.String())
	}
	firstID := decodeObject(t, first)["request_id"]

	second := f.post(t, body, copyHeaders(key))
	if second.Code != http.StatusOK {
		t.Fatalf("повтор должен давать 200, получено %d: %s", second.Code, second.Body.String())
	}
	payload := decodeObject(t, second)
	if payload["request_id"] != firstID {
		t.Fatalf("повтор вернул другую заявку: %v вместо %v", payload["request_id"], firstID)
	}
	if len(payload["packages"].([]any)) == 0 {
		t.Error("повтор должен возвращать состав заявки")
	}
}

// ---------------------------------------------------------------- файл зависимостей

func (f *createFixture) upload(t *testing.T, manager, filename, content string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("manager", manager)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	part, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/requests", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	f.authorize(t, req, map[string]string{})
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func TestCreateRequestFromRequirementsTxt(t *testing.T) {
	f := newCreateFixture(t)
	content := fmt.Sprintf("a-%s==1.0.0\nb-%s==2.0.0\nloose>=1.0\n", f.slug, f.slug)
	rec := f.upload(t, "pypi", "requirements.txt", content, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	if payload["accepted"] != float64(2) || payload["invalid"] != float64(1) {
		t.Fatalf("сводка: %v", payload)
	}
}

// go.sum перечисляет весь граф модулей — пользователь обязан это увидеть,
// иначе заявка на три пакета неожиданно становится заявкой на сто.
func TestCreateRequestFromGoSumWarns(t *testing.T) {
	f := newCreateFixture(t)
	content := fmt.Sprintf("example.com/a-%s v1.0.0 h1:x=\nexample.com/b-%s v2.0.0 h1:y=\n", f.slug, f.slug)
	rec := f.upload(t, "go", "go.sum", content, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	warnings := decodeObject(t, rec)["warnings"].([]any)
	joined := fmt.Sprint(warnings...)
	if !strings.Contains(joined, "весь граф модулей") {
		t.Fatalf("предупреждение про go.sum обязано быть: %v", warnings)
	}
}

// Транзитивные записи по умолчанию не заводятся, и пропуск объясняется.
func TestCreateRequestSkipsTransitiveByDefault(t *testing.T) {
	f := newCreateFixture(t)
	content := fmt.Sprintf(`module example.com/app

require (
	example.com/direct-%s v1.0.0
	example.com/indirect-%s v2.0.0 // indirect
)
`, f.slug, f.slug)

	rec := f.upload(t, "go", "go.mod", content, nil)
	payload := decodeObject(t, rec)
	if payload["accepted"] != float64(1) {
		t.Fatalf("принято %v, ожидалась одна прямая зависимость: %s", payload["accepted"], rec.Body.String())
	}
	joined := fmt.Sprint(payload["warnings"].([]any)...)
	if !strings.Contains(joined, "Транзитивных зависимостей в файле: 1") {
		t.Errorf("пропуск транзитивных обязан объясняться: %v", payload["warnings"])
	}

	// С include_transitive=true берутся обе.
	rec = f.upload(t, "go", "go.mod", content, map[string]string{"include_transitive": "true"})
	if decodeObject(t, rec)["accepted"] != float64(2) {
		t.Fatalf("с include_transitive должны заводиться обе: %s", rec.Body.String())
	}
}

func TestCreateRequestUploadValidation(t *testing.T) {
	f := newCreateFixture(t)
	if rec := f.upload(t, "pypi", "Gemfile.lock", "x", nil); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("чужой формат файла: код %d", rec.Code)
	}
	if rec := f.upload(t, "pypi", "requirements.txt", strings.Repeat("a==1.0.0\n", 20000), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("файл больше предела: код %d", rec.Code)
	}
}

func copyHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Перезапуск трогает только упавшие пакеты: перезапуск одобренного отозвал бы
// решение, а ждущего роли — обнулил бы ожидание.
func TestRetryOnlyFailedItems(t *testing.T) {
	f := newCreateFixture(t)
	ctx := context.Background()
	body := fmt.Sprintf(`{"manager":"pypi","packages":["r1-%s==1.0.0","r2-%s==1.0.0"]}`, f.slug, f.slug)
	created := decodeObject(t, f.post(t, body, nil))
	requestID := int64(created["request_id"].(float64))

	items, err := f.repo.ListItemsByRequest(ctx, requestID)
	if err != nil || len(items) != 2 {
		t.Fatalf("пакеты заявки: %v (%d)", err, len(items))
	}
	if err := f.repo.UpdateRequestItemStatus(ctx, items[0].ID, "failed", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.UpdateRequestItemStatus(ctx, items[1].ID, "approved", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/requests/%d/retry", requestID), strings.NewReader(""))
	f.authorize(t, req, map[string]string{})
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if decodeObject(t, rec)["restarted"] != float64(1) {
		t.Fatalf("перезапущено %v, ожидался один упавший пакет", decodeObject(t, rec)["restarted"])
	}

	after, _ := f.repo.ListItemsByRequest(ctx, requestID)
	for _, item := range after {
		switch item.ID {
		case items[0].ID:
			if item.Status != "queued" {
				t.Errorf("упавший пакет должен вернуться в очередь: %q", item.Status)
			}
		case items[1].ID:
			if item.Status != "approved" {
				t.Errorf("одобренный пакет трогать нельзя: %q", item.Status)
			}
		}
	}
}
