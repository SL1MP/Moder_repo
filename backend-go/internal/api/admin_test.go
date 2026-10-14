package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"moderation/internal/api"
	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/policy"
	"moderation/internal/queue"
	"moderation/internal/repo"
)

// Экран «Настройка» и журнал аудита.
//
// Экран существует ровно затем, чтобы «пакет вечно проверяется» и «почему
// сервис ведёт себя не так» не приходилось диагностировать по логам
// контейнеров. Поэтому проверяется не форма ответа, а то, отвечает ли он на
// эти вопросы.

type adminFixture struct {
	router   http.Handler
	repo     *repo.Repo
	verifier *auth.Verifier
	user     *domain.User
	policies *policy.Holder
	cfg      *config.Config
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	r, cleanup := mustRepo(t)
	t.Cleanup(cleanup)

	user, err := r.GetOrCreateUser(context.Background(),
		fmt.Sprintf("админ-%d", time.Now().UnixNano()), "Админ")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"DATABASE_URL": "postgres://не-используется", "LOCAL_AUTH_ENABLED": "true",
			"LOCAL_AUTH_SECRET": "секрет-админки", "ARTIFACT_TOKEN": "очень-секретный-токен",
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	policies := policy.NewHolder("../../../config/blacklist.yml", "../../../config/licenses.yml")
	verifier := auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil)

	swept := 0
	return &adminFixture{
		router: api.NewRouter(nil, api.Options{
			Auth: &api.AuthHandler{Auth: &api.Auth{Verifier: verifier, Repo: r}, Cfg: cfg},
			Admin: &api.AdminHandler{
				Policies: policies, Repo: r, Cfg: cfg,
				Queue: queue.New(r.Pool(), time.Minute),
				Sweep: func(context.Context) (int, error) { swept++; return swept, nil },
			},
		}),
		repo: r, verifier: verifier, user: user, policies: policies, cfg: cfg,
	}
}

// isolateBlacklistPolicy не даёт singleton-настройке протечь между
// интеграционными тестами или затереть данные уже существующей тестовой БД.
func isolateBlacklistPolicy(t *testing.T, r *repo.Repo) {
	t.Helper()
	ctx := context.Background()
	var oldRules string
	var oldActor *int64
	var oldUpdated time.Time
	err := r.Pool().QueryRow(ctx, `
		SELECT rules::text, updated_by_id, updated_at FROM blacklist_policy WHERE id = 1
	`).Scan(&oldRules, &oldActor, &oldUpdated)
	hadOld := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("снимок blacklist: %v", err)
	}
	if _, err := r.Pool().Exec(ctx, `DELETE FROM blacklist_policy WHERE id = 1`); err != nil {
		t.Fatalf("изоляция blacklist: %v", err)
	}
	t.Cleanup(func() {
		if hadOld {
			_, _ = r.Pool().Exec(context.Background(), `
				INSERT INTO blacklist_policy (id, rules, updated_by_id, updated_at)
				VALUES (1, $1::jsonb, $2, $3)
				ON CONFLICT (id) DO UPDATE SET rules = EXCLUDED.rules,
					updated_by_id = EXCLUDED.updated_by_id, updated_at = EXCLUDED.updated_at
			`, oldRules, oldActor, oldUpdated)
		} else {
			_, _ = r.Pool().Exec(context.Background(), `DELETE FROM blacklist_policy WHERE id = 1`)
		}
	})
}

func (f *adminFixture) do(t *testing.T, role, method, path string) *httptest.ResponseRecorder {
	return f.doBody(t, role, method, path, "{}")
}

func (f *adminFixture) doBody(
	t *testing.T, role, method, path, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	acting := *f.user
	acting.Roles = []string{role}
	acting.IsService = true
	token, _, err := f.verifier.IssueLocalToken(&acting)
	if err != nil {
		t.Fatalf("токен: %v", err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func TestWebSettingsAreAdminOnlyAndPersisted(t *testing.T) {
	f := newAdminFixture(t)
	body := `{"values":{"ARTIFACT_PUBLIC_BASE_URL":"https://repo.example.test:8443"}}`
	if rec := f.doBody(t, "developer", http.MethodPut, "/api/v1/settings", body); rec.Code != http.StatusForbidden {
		t.Fatalf("разработчик изменил настройки: %d %s", rec.Code, rec.Body.String())
	}

	listener, err := f.repo.Pool().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = listener.Exec(context.Background(), "UNLISTEN *")
		listener.Release()
	}()
	if _, err := listener.Exec(context.Background(), "LISTEN "+repo.AppSettingsChannel); err != nil {
		t.Fatal(err)
	}

	rec := f.doBody(t, "admin", http.MethodPut, "/api/v1/settings", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("настройка не сохранена: %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		RestartRequired  bool `json:"restart_required"`
		RestartScheduled bool `json:"restart_scheduled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.RestartRequired || !result.RestartScheduled {
		t.Fatalf("неверный режим применения настроек: %s", rec.Body.String())
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := listener.Conn().WaitForNotification(waitCtx); err != nil {
		t.Fatalf("процессы не уведомлены об изменении настроек: %v", err)
	}
	stored, err := f.repo.AppSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := stored["ARTIFACT_PUBLIC_BASE_URL"]; got != "https://repo.example.test:8443" {
		t.Fatalf("сохранено %q", got)
	}

	rec = f.do(t, "developer", http.MethodGet, "/api/v1/settings")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"value":"https://repo.example.test:8443"`) {
		t.Fatalf("сохранённое значение не видно в каталоге: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"overridden"`) {
		t.Fatalf("интерфейс раскрывает технический источник настройки: %s", rec.Body.String())
	}
}

func TestAdminCreatesLocalUserWithApplicationRoles(t *testing.T) {
	f := newAdminFixture(t)
	username := fmt.Sprintf("локальный-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"username":%q,"full_name":"Локальный пользователь",`+
		`"roles":["developer"],"source":"local","password":"надёжный-пароль"}`, username)
	rec := f.doBody(t, "admin", http.MethodPost, "/api/v1/admin/users", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("пользователь не создан: %d %s", rec.Code, rec.Body.String())
	}

	created, err := f.repo.GetUserByUsername(context.Background(), username)
	if err != nil || created == nil {
		t.Fatalf("пользователь не найден: %v", err)
	}
	if created.IsService || !created.HasRole("developer") {
		t.Fatalf("неверный тип или роли: %+v", created)
	}
	if !auth.VerifyPassword("надёжный-пароль", created.PasswordHash) {
		t.Fatal("сохранённый пароль не проверяется")
	}
}

func TestAdminDeletesUserWithoutDestroyingHistory(t *testing.T) {
	f := newAdminFixture(t)
	username := fmt.Sprintf("удаляемый-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"username":%q,"roles":["developer"],"password":"надёжный-пароль"}`, username)
	createdRec := f.doBody(t, "admin", http.MethodPost, "/api/v1/admin/users", body)
	if createdRec.Code != http.StatusCreated {
		t.Fatalf("пользователь не создан: %d %s", createdRec.Code, createdRec.Body.String())
	}
	var created struct{ ID int64 `json:"id"` }
	if err := json.Unmarshal(createdRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	deletedRec := f.do(t, "admin", http.MethodDelete,
		fmt.Sprintf("/api/v1/admin/users/%d", created.ID))
	if deletedRec.Code != http.StatusOK {
		t.Fatalf("пользователь не удалён: %d %s", deletedRec.Code, deletedRec.Body.String())
	}
	if user, err := f.repo.GetUserByID(context.Background(), created.ID); err != nil || user != nil {
		t.Fatalf("удалённый пользователь доступен в админке: user=%+v err=%v", user, err)
	}
}

// TestSettingsShowEnvNames — настройка показывается вместе с именем
// переменной.
//
// Это не украшение: администратор смотрит сюда, чтобы понять, почему сервис
// ведёт себя не так, как он ожидал. «QUARANTINE_DAYS = 14» закрывает вопрос за
// секунду, а «карантин: 14 дней» оставляет искать, где это правится.
func TestSettingsShowEnvNames(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.do(t, "developer", http.MethodGet, "/api/v1/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	var settings []struct {
		Env     string `json:"env"`
		Section string `json:"section"`
		Value   any    `json:"value"`
		Secret  bool   `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &settings); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	if len(settings) < 20 {
		t.Fatalf("настроек в ответе: %d — каталог выглядит обрезанным", len(settings))
	}

	byEnv := map[string]any{}
	secrets := map[string]bool{}
	for _, s := range settings {
		if s.Env == "" || s.Section == "" {
			t.Errorf("настройка без имени или раздела: %+v", s)
		}
		byEnv[s.Env] = s.Value
		secrets[s.Env] = s.Secret
	}
	for _, env := range []string{
		"QUARANTINE_DAYS", "ARTIFACT_REPO_STAGING", "SANDBOX_URL",
		"OSV_DB_SOURCE", "RATE_LIMIT_REQUESTS_PER_MINUTE",
	} {
		if _, ok := byEnv[env]; !ok {
			t.Errorf("в каталоге нет %s", env)
		}
	}

	// Секреты показываются маской той же длины. Значение не показывается
	// никогда: экран открыт всем ролям.
	if !secrets["ARTIFACT_TOKEN"] {
		t.Error("ARTIFACT_TOKEN не помечен секретом")
	}
	wantMask := strings.Repeat("*", utf8.RuneCountInString("очень-секретный-токен"))
	if byEnv["ARTIFACT_TOKEN"] != wantMask {
		t.Errorf("маска ARTIFACT_TOKEN = %v, ожидалась %q", byEnv["ARTIFACT_TOKEN"], wantMask)
	}
	if strings.Contains(rec.Body.String(), "очень-секретный-токен") {
		t.Error("значение секрета утекло в ответ")
	}
}

func TestOIDCSettingsReturnOnlySecretMask(t *testing.T) {
	f := newAdminFixture(t)
	const secret = "oidc-secret-42"
	if err := f.repo.UpdateOIDCSettings(context.Background(), repo.OIDCSettings{
		Enabled: true, Issuer: "https://idp.example.test/realms/internal",
		ClientID: "moderation", ClientSecret: secret,
		PublicBaseURL: "https://moderation.example.test", ButtonLabel: "SSO",
	}); err != nil {
		t.Fatal(err)
	}

	rec := f.do(t, "admin", http.MethodGet, "/api/v1/admin/integrations/oidc")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("OIDC client secret утёк в ответ")
	}
	var payload struct {
		SecretSet  bool   `json:"secret_set"`
		SecretMask string `json:"secret_mask"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.SecretSet || payload.SecretMask != strings.Repeat("*", len(secret)) {
		t.Fatalf("неверная маска OIDC-секрета: %+v", payload)
	}
}

// TestPoliciesStateReportsFiles — состояние политик отвечает на вопрос
// «прочитаны ли файлы», а не только «что в них».
func TestPoliciesStateReportsFiles(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.do(t, "developer", http.MethodGet, "/api/v1/settings/policies")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Blacklist struct {
			Path  string `json:"path"`
			Error string `json:"error"`
		} `json:"blacklist"`
		Licenses struct {
			Path    string           `json:"path"`
			Allowed []map[string]any `json:"allowed"`
			Error   string           `json:"error"`
		} `json:"licenses"`
		VulnIndex struct {
			Stale            bool `json:"stale"`
			MaxStalenessDays int  `json:"max_staleness_days"`
		} `json:"vuln_index"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	if payload.Blacklist.Path == "" || payload.Licenses.Path == "" {
		t.Error("пути файлов политик не показаны — чинить нечего будет")
	}
	if payload.Blacklist.Error != "" {
		t.Errorf("blacklist не прочитан: %s", payload.Blacklist.Error)
	}
	if len(payload.Licenses.Allowed) == 0 {
		t.Error("справочник лицензий пуст")
	}
	// Снапшот в тесте не загружен — и это должно быть видно как «устарел»,
	// а не как «свежий»: «не знаем» и «свежий» разные вещи.
	if !payload.VulnIndex.Stale {
		t.Error("незагруженный снапшот показан не устаревшим")
	}
	if payload.VulnIndex.MaxStalenessDays == 0 {
		t.Error("порог устаревания не показан — непонятно, относительно чего судить")
	}
}

func TestAdminEditsBlacklistAndDeveloperCannot(t *testing.T) {
	f := newAdminFixture(t)
	isolateBlacklistPolicy(t, f.repo)
	ctx := context.Background()

	body := `{"rules":[{"manager":"npm","name":"event-*","versions":"==3.3.6","reason":"известный бэкдор"}]}`
	if rec := f.doBody(t, "developer", http.MethodPut, "/api/v1/admin/policies/blacklist", body); rec.Code != http.StatusForbidden {
		t.Fatalf("разработчик изменил blacklist: %d %s", rec.Code, rec.Body.String())
	}
	invalid := `{"rules":[{"manager":"npm","name":"[","versions":"*","reason":"ошибка"}]}`
	if rec := f.doBody(t, "admin", http.MethodPut, "/api/v1/admin/policies/blacklist", invalid); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("сломанный glob принят: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.doBody(t, "admin", http.MethodPut, "/api/v1/admin/policies/blacklist", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("blacklist не сохранён: %d %s", rec.Code, rec.Body.String())
	}
	if f.policies.Blacklist().Find("npm", "event-stream", "3.3.6") == nil {
		t.Fatal("сохранённое правило не применилось в текущем API")
	}
	rules, configured, err := f.repo.BlacklistRules(ctx)
	if err != nil || !configured || len(rules) != 1 {
		t.Fatalf("правила не сохранились в БД: configured=%v rules=%+v err=%v", configured, rules, err)
	}
	if rules[0].AddedBy != f.user.Username || rules[0].AddedAt == "" {
		t.Fatalf("сервер не заполнил аудит правила: %+v", rules[0])
	}
}

// TestSystemStatusShowsStuckItems — экран показывает залежавшиеся пакеты
// поимённо, а не только их число: именно по ним разбирают «пакет вечно
// проверяется».
func TestSystemStatusShowsStuckItems(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.do(t, "developer", http.MethodGet, "/api/v1/system/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Queue map[string]any `json:"queue"`
		Watch map[string]any `json:"watchdog"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	for _, key := range []string{"queued", "running", "stuck_items"} {
		if _, ok := payload.Queue[key]; !ok {
			t.Errorf("в состоянии очереди нет %q: %v", key, payload.Queue)
		}
	}
	if _, ok := payload.Watch["stuck_after_seconds"]; !ok {
		t.Errorf("не показан порог, после которого пакет считается зависшим: %v", payload.Watch)
	}
}

func TestArtifactCatalogSyncIsVisibleAndAdminStartsIt(t *testing.T) {
	f := newAdminFixture(t)
	f.cfg.ArtifactCatalogSyncManagers = []string{"pypi", "npm", "go"}

	if rec := f.do(t, "developer", http.MethodGet, "/api/v1/artifact-catalog-sync"); rec.Code != http.StatusOK {
		t.Fatalf("состояние синхронизации не прочитано: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, "developer", http.MethodPost, "/api/v1/admin/artifact-catalog-sync"); rec.Code != http.StatusForbidden {
		t.Fatalf("разработчик запустил синхронизацию: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.do(t, "admin", http.MethodPost, "/api/v1/admin/artifact-catalog-sync")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("синхронизация не поставлена в очередь: %d %s", rec.Code, rec.Body.String())
	}
	var run struct {
		ID            int64  `json:"id"`
		Status        string `json:"status"`
		RequestedByID *int64 `json:"requested_by_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.RequestedByID != nil && *run.RequestedByID == f.user.ID {
		t.Cleanup(func() {
			_, _ = f.repo.Pool().Exec(context.Background(),
				`DELETE FROM artifact_catalog_sync_run WHERE id = $1`, run.ID)
		})
	}
	if !strings.Contains(rec.Body.String(), `"status":"queued"`) &&
		!strings.Contains(rec.Body.String(), `"status":"running"`) {
		t.Fatalf("неожиданный запуск синхронизации: %s", rec.Body.String())
	}
}

// TestAuditIsAdminOnly — журнал видит только админ: в нём видно, кто что решал
// по каждому пакету.
func TestAuditIsAdminOnly(t *testing.T) {
	f := newAdminFixture(t)
	if rec := f.do(t, "developer", http.MethodGet, "/api/v1/admin/audit"); rec.Code != http.StatusForbidden {
		t.Errorf("разработчику отдан журнал аудита (код %d)", rec.Code)
	}
	if rec := f.do(t, "admin", http.MethodGet, "/api/v1/admin/audit"); rec.Code != http.StatusOK {
		t.Errorf("админу журнал не отдан: %d %s", rec.Code, rec.Body.String())
	}
}

// TestAuditFiltersByEntity — прицельный отбор, а не пролистывание сотен строк.
func TestAuditFiltersByEntity(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	entityID := fmt.Sprintf("%d", time.Now().UnixNano())

	for _, action := range []string{"package_revoked", "policies_reloaded"} {
		if err := f.repo.InsertAuditLog(ctx, domain.AuditLog{
			ActorID: &f.user.ID, ActorName: f.user.Username,
			Action: action, EntityType: "проверка-фильтра", EntityID: &entityID,
			Source: "ui", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Отбираем по УНИКАЛЬНОМУ идентификатору, а не по типу сущности: база
	// между прогонами `go test` не пересоздаётся, и записи прошлых прогонов
	// с тем же типом никуда не делись. Тест, отбирающий по общему полю,
	// краснеет через раз — и это не про код, а про фикстуру.
	rec := f.do(t, "admin", http.MethodGet,
		"/api/v1/admin/audit?entity_id="+entityID+"&action=package_revoked")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var entries []struct {
		Action      string `json:"action"`
		SourceTitle string `json:"source_title"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей после отбора: %d, ожидалась 1: %s", len(entries), rec.Body.String())
	}
	if entries[0].Action != "package_revoked" {
		t.Errorf("отобрано не то действие: %q", entries[0].Action)
	}
	// Источник показывается по-человечески: «ui» в журнале читает человек.
	if entries[0].SourceTitle != "UI" {
		t.Errorf("источник = %q, ожидалось «UI»", entries[0].SourceTitle)
	}
}

// TestQueueSweepIsAdminOnlyAndAudited — ручной прогон очереди меняет состояние
// сервиса, поэтому доступен только админу и остаётся в журнале.
func TestQueueSweepIsAdminOnlyAndAudited(t *testing.T) {
	f := newAdminFixture(t)
	if rec := f.do(t, "devsecops", http.MethodPost, "/api/v1/admin/queue-sweep"); rec.Code != http.StatusForbidden {
		t.Errorf("прогон очереди доступен не админу (код %d)", rec.Code)
	}

	rec := f.do(t, "admin", http.MethodPost, "/api/v1/admin/queue-sweep")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	entries, err := f.repo.ListAuditLog(context.Background(),
		repo.AuditFilter{Action: "queue_swept", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Error("прогон очереди не записан в журнал")
	}
}

// TestReloadKeepsWorkingRulesOnBrokenFile — перезагрузка со сломанным файлом
// отвечает 422 и НЕ снимает действующие запреты.
//
// Отдать 200 нельзя: администратор увидел бы «перезагружено» и ушёл, а
// работали бы прежние правила. Снять запреты тоже нельзя — опечатка в файле
// открыла бы контур ровно тогда, когда его правят второпях.
func TestReloadKeepsWorkingRulesOnBrokenFile(t *testing.T) {
	r, cleanup := mustRepo(t)
	t.Cleanup(cleanup)
	isolateBlacklistPolicy(t, r)

	dir := t.TempDir()
	blPath := dir + "/blacklist.yml"
	licPath := dir + "/licenses.yml"
	writeTestFile(t, blPath, "rules:\n  - manager: pypi\n    name: badpkg\n    reason: тест\n")
	writeTestFile(t, licPath, "licenses:\n  - spdx_id: MIT\n    name: MIT\n    allowed: true\n")

	user, err := r.GetOrCreateUser(context.Background(),
		fmt.Sprintf("админ-reload-%d", time.Now().UnixNano()), "Админ")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"DATABASE_URL": "postgres://не-используется", "LOCAL_AUTH_ENABLED": "true",
			"LOCAL_AUTH_SECRET": "секрет",
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	policies := policy.NewHolder(blPath, licPath)
	verifier := auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil)
	router := api.NewRouter(nil, api.Options{
		Auth:  &api.AuthHandler{Auth: &api.Auth{Verifier: verifier, Repo: r}, Cfg: cfg},
		Admin: &api.AdminHandler{Policies: policies, Repo: r, Cfg: cfg},
	})

	call := func() *httptest.ResponseRecorder {
		acting := *user
		acting.Roles = []string{"admin"}
		acting.IsService = true
		token, _, err := verifier.IssueLocalToken(&acting)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reload", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	if rec := call(); rec.Code != http.StatusOK {
		t.Fatalf("исправные файлы дали код %d: %s", rec.Code, rec.Body.String())
	}

	writeTestFile(t, blPath, "rules: [ не yaml : : :")
	rec := call()
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("сломанный файл дал код %d, ожидался 422", rec.Code)
	}
	if policies.Blacklist().Find("pypi", "badpkg", "1.0.0") == nil {
		t.Error("сломанный файл снял действующие запреты")
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := osWriteFile(path, body); err != nil {
		t.Fatal(err)
	}
}

func osWriteFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}
