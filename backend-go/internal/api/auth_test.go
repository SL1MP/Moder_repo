package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/repo"
)

// ---------------------------------------------------------------- инструменты

// memStore — учётки в памяти. Проверка доступа — единственное место, где до
// Postgres дело доходит на КАЖДОМ запросе, и её поведение надо проверять
// целиком, включая отказы; поднимать ради этого базу не нужно.
type memStore struct {
	mu        sync.Mutex
	byName    map[string]*domain.User
	audit     []domain.AuditLog
	syncCalls int
	failSync  error
}

func newMemStore(users ...*domain.User) *memStore {
	s := &memStore{byName: map[string]*domain.User{}}
	for _, u := range users {
		s.byName[u.Username] = u
	}
	return s
}

func (s *memStore) SyncUser(_ context.Context, claims repo.UserClaims, now time.Time) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncCalls++
	if s.failSync != nil {
		return nil, s.failSync
	}
	user, ok := s.byName[claims.Username]
	if !ok {
		user = &domain.User{
			ID: int64(len(s.byName) + 1), Username: claims.Username,
			IsService: claims.IsService, IsActive: true,
		}
		s.byName[claims.Username] = user
	}
	if len(claims.Roles) > 0 {
		user.Roles = claims.Roles
	}
	user.LastLoginAt = &now
	return user, nil
}

func (s *memStore) GetUserByUsername(_ context.Context, username string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byName[username], nil
}

func (s *memStore) TouchLastLogin(_ context.Context, userID int64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.byName {
		if u.ID == userID {
			u.LastLoginAt = &now
		}
	}
	return nil
}

func (s *memStore) InsertAuditLog(_ context.Context, entry domain.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, entry)
	return nil
}

func (s *memStore) auditActions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.audit))
	for _, e := range s.audit {
		out = append(out, e.Action)
	}
	return out
}

func testConfig(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	base := map[string]string{
		"DATABASE_URL":       "postgres://x/y",
		"LOCAL_AUTH_ENABLED": "true",
		"LOCAL_AUTH_SECRET":  "секрет-для-теста",
		"OIDC_ISSUER":        "http://keycloak:8080/realms/moderation",
		"OIDC_PUBLIC_ISSUER": "https://moderated-repo.example.com/realms/moderation",
	}
	for k, v := range env {
		base[k] = v
	}
	cfg, err := config.Load(func(key string) string { return base[key] })
	if err != nil {
		t.Fatalf("конфигурация теста невалидна: %v", err)
	}
	return cfg
}

type harness struct {
	router http.Handler
	store  *memStore
	cfg    *config.Config
	auth   *Auth
}

func newHarness(t *testing.T, store *memStore, env map[string]string) *harness {
	t.Helper()
	cfg := testConfig(t, env)
	a := &Auth{
		Verifier: auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, func() time.Time { return testNow }),
		Repo:     store,
		Now:      func() time.Time { return testNow },
	}
	h := &harness{store: store, cfg: cfg, auth: a}
	h.router = NewRouter(nil, Options{Auth: &AuthHandler{Auth: a, Cfg: cfg}})
	return h
}

var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func (h *harness) do(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("ответ не разбирается как JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return payload
}

func errorPayloadOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	payload := decode(t, rec)
	body, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("ошибка должна быть объектом {code, message, details, request_id}, получено: %s", rec.Body.String())
	}
	return body
}

// ---------------------------------------------------------------- /auth/config

// Состав ответа проверяется по списку полей: SPA читает их по именам, и
// потерянное поле ломает вход молча — без ошибки, просто пустым экраном.
func TestAuthConfigShape(t *testing.T) {
	h := newHarness(t, newMemStore(), map[string]string{
		"APP_NAME":       "Модерация пакетов",
		"APP_ENV":        "prod",
		"GITLAB_URL":     "https://gitlab.example.com",
		"OIDC_CLIENT_ID": "moderation-web",
	})
	rec := h.do(t, http.MethodGet, "/api/v1/auth/config", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("config должен быть открыт без токена, получено %d", rec.Code)
	}
	payload := decode(t, rec)

	for _, field := range []string{
		"issuer", "client_id", "scopes", "flow", "local_auth_enabled",
		"app_name", "app_env", "gitlab_enabled", "role_mapping",
	} {
		if _, ok := payload[field]; !ok {
			t.Errorf("в ответе нет поля %q — SPA читает его по имени", field)
		}
	}
	// Издатель — ВНЕШНИЙ: по нему в Keycloak пойдёт браузер.
	if payload["issuer"] != "https://moderated-repo.example.com/realms/moderation" {
		t.Errorf("issuer должен быть внешним адресом, получено %v", payload["issuer"])
	}
	if payload["app_name"] != "Модерация пакетов" {
		t.Errorf("app_name: %v", payload["app_name"])
	}
	// GITLAB_URL задан, а GITLAB_OAUTH_CLIENT_ID нет — интеграции нет.
	if payload["gitlab_enabled"] != false {
		t.Errorf("gitlab_enabled должен быть false без GITLAB_OAUTH_CLIENT_ID, получено %v", payload["gitlab_enabled"])
	}
	mapping, ok := payload["role_mapping"].(map[string]any)
	if !ok || mapping["devsecops"] != "moderation-devsecops" {
		t.Errorf("role_mapping разобран неверно: %v", payload["role_mapping"])
	}
	if payload["flow"] != "authorization_code_pkce" {
		t.Errorf("flow: %v", payload["flow"])
	}
}

// Кириллица не должна экранироваться: ответ читают и люди (в логах, в
// devtools), а Мо... нечитаемо.
func TestAuthConfigNotEscaped(t *testing.T) {
	h := newHarness(t, newMemStore(), map[string]string{"APP_NAME": "Модерация пакетов"})
	rec := h.do(t, http.MethodGet, "/api/v1/auth/config", "", "")
	if !strings.Contains(rec.Body.String(), "Модерация пакетов") {
		t.Fatalf("кириллица экранирована: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------- /auth/me

func TestMeRequiresToken(t *testing.T) {
	h := newHarness(t, newMemStore(), nil)

	cases := []struct{ name, header string }{
		{"без заголовка", ""},
		{"не Bearer", "Basic dXNlcjpwYXNz"},
		{"мусор вместо токена", "Bearer не-токен"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("ожидался 401, получено %d: %s", rec.Code, rec.Body.String())
			}
			body := errorPayloadOf(t, rec)
			if body["code"] != "unauthorized" {
				t.Fatalf("код ошибки должен быть unauthorized, получено %v", body["code"])
			}
			if body["message"] == "" {
				t.Fatal("сообщение об отказе не должно быть пустым")
			}
		})
	}
}

func TestMeReturnsProfile(t *testing.T) {
	full := "Иван Иванов"
	user := &domain.User{ID: 42, Username: "ivanov", FullName: &full,
		Roles: []string{"legal"}, IsActive: true}
	store := newMemStore(user)
	h := newHarness(t, store, nil)

	token := issueToken(t, h, user)
	rec := h.do(t, http.MethodGet, "/api/v1/auth/me", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получено %d: %s", rec.Code, rec.Body.String())
	}
	payload := decode(t, rec)
	if payload["username"] != "ivanov" || payload["display_name"] != full {
		t.Fatalf("профиль разобран неверно: %v", payload)
	}
	if payload["email"] != nil {
		t.Fatalf("незаполненный email должен быть null, получено %v", payload["email"])
	}
	roles, ok := payload["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != "legal" {
		t.Fatalf("роли: %v", payload["roles"])
	}
	// Учётка без ролей обязана отдавать [], а не null: SPA делает roles.map().
	if payload["gitlab_connected"] != false {
		t.Fatalf("gitlab_connected: %v", payload["gitlab_connected"])
	}
}

func TestMeRolesNeverNull(t *testing.T) {
	user := &domain.User{ID: 1, Username: "без-ролей", IsActive: true}
	h := newHarness(t, newMemStore(user), nil)
	rec := h.do(t, http.MethodGet, "/api/v1/auth/me", issueToken(t, h, user), "")
	if !strings.Contains(rec.Body.String(), `"roles":[]`) {
		t.Fatalf("roles должен быть пустым списком, а не null: %s", rec.Body.String())
	}
}

// Отключённая учётка не должна работать по уже выпущенному токену: отзыв
// доступа обязан действовать сразу, а не после истечения токена.
func TestDisabledUserRejected(t *testing.T) {
	user := &domain.User{ID: 5, Username: "уволен", Roles: []string{"developer"}, IsActive: true}
	store := newMemStore(user)
	h := newHarness(t, store, nil)
	token := issueToken(t, h, user)

	user.IsActive = false
	rec := h.do(t, http.MethodGet, "/api/v1/auth/me", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ожидался 403, получено %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "отключена") {
		t.Fatalf("сообщение должно объяснять причину: %s", rec.Body.String())
	}
}

// Упавшая база — это 500, а не 401: «сервис сломался» и «вам сюда нельзя» —
// разные вещи, и путать их нельзя ни в ответе, ни в логах.
func TestStoreFailureIsNotUnauthorized(t *testing.T) {
	user := &domain.User{ID: 1, Username: "ivanov", Roles: []string{"admin"}, IsActive: true}
	store := newMemStore(user)
	h := newHarness(t, store, nil)
	token := issueToken(t, h, user)

	store.failSync = errUpstream("Postgres прилёг")
	rec := h.do(t, http.MethodGet, "/api/v1/auth/me", token, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("ожидался 500, получено %d: %s", rec.Code, rec.Body.String())
	}
	// Наружу не должно уходить, что именно сломалось внутри.
	if strings.Contains(rec.Body.String(), "Postgres") {
		t.Fatalf("техническая причина не должна уходить клиенту: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------- /auth/token

func TestLocalLogin(t *testing.T) {
	hash, err := auth.HashPassword("пароль-сервисной-учётки")
	if err != nil {
		t.Fatalf("хеширование: %v", err)
	}
	user := &domain.User{ID: 9, Username: "ci-bot", PasswordHash: &hash,
		Roles: []string{"devsecops"}, IsService: true, IsActive: true}
	store := newMemStore(user)
	h := newHarness(t, store, nil)

	rec := h.do(t, http.MethodPost, "/api/v1/auth/token", "",
		`{"username":"ci-bot","password":"пароль-сервисной-учётки"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получено %d: %s", rec.Code, rec.Body.String())
	}
	payload := decode(t, rec)
	if payload["token_type"] != "bearer" {
		t.Fatalf("token_type: %v", payload["token_type"])
	}
	if payload["expires_in"] != float64(480*60) {
		t.Fatalf("expires_in должен быть в секундах: %v", payload["expires_in"])
	}
	token, _ := payload["access_token"].(string)
	if token == "" {
		t.Fatal("токен не выдан")
	}

	// Выданный токен обязан работать на закрытом маршруте — иначе вход
	// «успешен», а пользоваться им нельзя.
	me := h.do(t, http.MethodGet, "/api/v1/auth/me", token, "")
	if me.Code != http.StatusOK {
		t.Fatalf("выданный токен не принят: %d %s", me.Code, me.Body.String())
	}
	if got := store.auditActions(); len(got) != 1 || got[0] != "local_login" {
		t.Fatalf("удачный вход должен попасть в аудит: %v", got)
	}
}

func TestLocalLoginDenied(t *testing.T) {
	hash, _ := auth.HashPassword("верный-пароль")
	user := &domain.User{ID: 9, Username: "ci-bot", PasswordHash: &hash,
		Roles: []string{"devsecops"}, IsService: true, IsActive: true}

	cases := []struct {
		name string
		body string
		user *domain.User
	}{
		{"неверный пароль", `{"username":"ci-bot","password":"не-тот"}`, user},
		{"нет такой учётки", `{"username":"никого","password":"верный-пароль"}`, user},
		{"учётка отключена", `{"username":"ci-bot","password":"верный-пароль"}`,
			&domain.User{ID: 9, Username: "ci-bot", PasswordHash: &hash, IsActive: false}},
		{"учётка без пароля", `{"username":"ci-bot","password":"верный-пароль"}`,
			&domain.User{ID: 9, Username: "ci-bot", IsActive: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore(tc.user)
			h := newHarness(t, store, nil)
			rec := h.do(t, http.MethodPost, "/api/v1/auth/token", "", tc.body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("ожидался 401, получено %d: %s", rec.Code, rec.Body.String())
			}
			// Ответ одинаков во всех четырёх случаях: иначе по разнице
			// ответов перебирается список существующих учёток.
			if body := errorPayloadOf(t, rec); body["message"] != "Неверный логин или пароль" {
				t.Fatalf("ответ не должен выдавать, что именно не сошлось: %v", body["message"])
			}
			if got := store.auditActions(); len(got) != 1 || got[0] != "local_login_failed" {
				t.Fatalf("неудачный вход должен попасть в аудит: %v", got)
			}
		})
	}
}

func TestLocalLoginDisabled(t *testing.T) {
	store := newMemStore()
	h := newHarness(t, store, map[string]string{"LOCAL_AUTH_ENABLED": "false"})

	rec := h.do(t, http.MethodPost, "/api/v1/auth/token", "", `{"username":"ci-bot","password":"x"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "LOCAL_AUTH_ENABLED") {
		t.Fatalf("сообщение должно называть флаг: %s", rec.Body.String())
	}
	// До базы дело дойти не должно вовсе.
	if len(store.auditActions()) != 0 {
		t.Fatalf("при выключенном входе учётки не проверяются: %v", store.auditActions())
	}
	// /auth/config при этом обязан отвечать: по нему SPA и понимает, что
	// формы логина показывать не нужно.
	cfgRec := h.do(t, http.MethodGet, "/api/v1/auth/config", "", "")
	if decode(t, cfgRec)["local_auth_enabled"] != false {
		t.Fatal("config должен сообщать, что локальный вход выключен")
	}
}

func TestLocalLoginBadBody(t *testing.T) {
	h := newHarness(t, newMemStore(), nil)
	for _, body := range []string{``, `не json`, `{"username":"ci-bot"}`} {
		rec := h.do(t, http.MethodPost, "/api/v1/auth/token", "", body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("тело %q: ожидался 422, получено %d", body, rec.Code)
		}
	}
}

// ---------------------------------------------------------------- RBAC

func TestRequireRoles(t *testing.T) {
	cases := []struct {
		name   string
		roles  []string
		need   []string
		status int
	}{
		{"своя роль", []string{"legal"}, []string{"legal"}, http.StatusOK},
		{"одна из двух", []string{"devsecops"}, []string{"legal", "devsecops"}, http.StatusOK},
		{"admin вхож всюду", []string{"admin"}, []string{"legal"}, http.StatusOK},
		{"чужая роль", []string{"developer"}, []string{"legal"}, http.StatusForbidden},
		{"совсем без ролей", nil, []string{"legal"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := &domain.User{ID: 1, Username: "ivanov", Roles: tc.roles, IsActive: true}
			h := newHarness(t, newMemStore(user), nil)
			token := issueToken(t, h, user)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/secret", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			guarded(h.auth, RequireRoles(tc.need...)).ServeHTTP(rec, req)

			if rec.Code != tc.status {
				t.Fatalf("ожидался %d, получено %d: %s", tc.status, rec.Code, rec.Body.String())
			}
			if tc.status == http.StatusForbidden {
				// Отказ обязан называть нужные роли по-русски: без этого
				// пользователь не понимает, что просить у администратора.
				if !strings.Contains(rec.Body.String(), "юрист") {
					t.Fatalf("сообщение должно называть роль: %s", rec.Body.String())
				}
			}
		})
	}
}

func TestRequireAnyRole(t *testing.T) {
	withRole := &domain.User{ID: 1, Username: "ivanov", Roles: []string{"developer"}, IsActive: true}
	h := newHarness(t, newMemStore(withRole), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.Header.Set("Authorization", "Bearer "+issueToken(t, h, withRole))
	guarded(h.auth, func(next http.Handler) http.Handler { return RequireAnyRole(next) }).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("роль есть — доступ должен быть: %d %s", rec.Code, rec.Body.String())
	}

	noRole := &domain.User{ID: 2, Username: "новичок", IsActive: true}
	h2 := newHarness(t, newMemStore(noRole), nil)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req2.Header.Set("Authorization", "Bearer "+issueToken(t, h2, noRole))
	guarded(h2.auth, func(next http.Handler) http.Handler { return RequireAnyRole(next) }).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("ожидался 403, получено %d", rec2.Code)
	}
	// Учётка без единой роли — почти всегда незаданный маппинг групп, а не
	// «нет прав»; сообщение обязано вести к причине.
	if !strings.Contains(rec2.Body.String(), "ROLE_MAPPING_") {
		t.Fatalf("сообщение должно указывать на маппинг групп: %s", rec2.Body.String())
	}
}

// ---------------------------------------------------------------- request_id

func TestRequestIDEchoedAndGenerated(t *testing.T) {
	h := newHarness(t, newMemStore(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("x-request-id", "пришёл-снаружи")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	if got := rec.Header().Get("x-request-id"); got != "пришёл-снаружи" {
		t.Fatalf("идентификатор из заголовка должен сохраняться, получено %q", got)
	}
	// И попасть в тело ошибки: по нему ответ связывается с записью в логе.
	if errorPayloadOf(t, rec)["request_id"] != "пришёл-снаружи" {
		t.Fatalf("request_id должен быть в теле ошибки: %s", rec.Body.String())
	}

	rec2 := h.do(t, http.MethodGet, "/api/v1/auth/me", "", "")
	generated := rec2.Header().Get("x-request-id")
	if len(generated) != 32 {
		t.Fatalf("сгенерированный идентификатор должен быть hex uuid4 (32 символа), получено %q", generated)
	}
}

// ---------------------------------------------------------------- отчёты закрыты

// Маршруты отчётов до этой фазы были открыты. В отчёте видны пути внутри
// пакета и фрагменты исходного кода — открытыми они остаться не могут.
func TestReportsRoutesRequireToken(t *testing.T) {
	h := newHarness(t, newMemStore(), nil)
	router := NewRouter(nil, Options{
		Auth:    &AuthHandler{Auth: h.auth, Cfg: h.cfg},
		Reports: &ReportsHandler{},
	})
	for _, path := range []string{
		"/api/v1/request-items/12/reports",
		"/api/v1/request-items/12/reports/sast_scan.json",
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: ожидался 401, получено %d", path, rec.Code)
		}
	}
}

// Без настроенной проверки токенов маршруты отчётов не подключаются вовсе:
// открытыми они быть не могут даже при кривой конфигурации.
func TestReportsNotMountedWithoutAuth(t *testing.T) {
	router := NewRouter(nil, Options{Reports: &ReportsHandler{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/request-items/12/reports", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("маршрут не должен существовать, получено %d", rec.Code)
	}
}

// ---------------------------------------------------------------- вспомогательное

// issueToken выпускает локальный токен от имени пользователя — так тесты
// проходят весь путь проверки, а не подсовывают готовые claims.
func issueToken(t *testing.T, h *harness, user *domain.User) string {
	t.Helper()
	token, _, err := h.auth.Verifier.IssueLocalToken(user)
	if err != nil {
		t.Fatalf("выпуск тестового токена: %v", err)
	}
	return token
}

// guarded собирает маршрут «проверка токена → проверка роли → обработчик».
func guarded(a *Auth, guard func(http.Handler) http.Handler) http.Handler {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return withRequestID(a.Authenticate(guard(ok)))
}
