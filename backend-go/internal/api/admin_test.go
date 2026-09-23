package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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

func (f *adminFixture) do(t *testing.T, role, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	acting := *f.user
	acting.Roles = []string{role}
	token, _, err := f.verifier.IssueLocalToken(&acting)
	if err != nil {
		t.Fatalf("токен: %v", err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
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

	// Секреты показываются как «задано»/«не задано». Значение не
	// показывается никогда: экран открыт всем ролям.
	if !secrets["ARTIFACT_TOKEN"] {
		t.Error("ARTIFACT_TOKEN не помечен секретом")
	}
	if byEnv["ARTIFACT_TOKEN"] != "задано" {
		t.Errorf("значение ARTIFACT_TOKEN = %v, ожидалось «задано»", byEnv["ARTIFACT_TOKEN"])
	}
	if strings.Contains(rec.Body.String(), "очень-секретный-токен") {
		t.Error("значение секрета утекло в ответ")
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
	defer cleanup()

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
