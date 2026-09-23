package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"moderation/internal/api"
	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

func mustRepo(t *testing.T) (*repo.Repo, func()) {
	t.Helper()
	dsn := os.Getenv("MODERATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MODERATION_TEST_POSTGRES_DSN не задан — пропускаю интеграционный тест (см. docs/testing.md)")
	}
	pool, err := db.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("подключение к тестовому Postgres: %v", err)
	}
	return repo.New(pool), func() { pool.Close() }
}

// fixture создаёт пакет заявки с отчётом и его файлами в хранилище.
func fixture(t *testing.T, r *repo.Repo, store storage.Store, state string) (int64, *domain.ScanReport) {
	t.Helper()
	ctx := context.Background()
	slug := testSlug(t)

	user, err := r.GetOrCreateUser(ctx, "api-"+slug, "API тест")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := r.GetOrCreatePackage(ctx, "pypi", "rep-"+slug, "rep-"+slug)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: user.ID, Manager: "pypi", Status: "pending", Source: "ui",
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req.ID, PackageVersionID: ver.ID,
		RequestedName: pkg.Name, RequestedVersion: "1.0.0",
		DependencyKind: "direct", Status: "awaiting_security",
	})
	if err != nil {
		t.Fatal(err)
	}

	jsonKey := storage.ReportKey(item.ID, "sandbox_scan", "json")
	htmlKey := storage.ReportKey(item.ID, "sandbox_scan", "html")
	if _, err := store.Put(ctx, jsonKey,
		[]byte(`{"schema":"moderation.scan-report/v1","summary":{"blocking":1},"detail":"кириллица"}`),
		storage.ContentTypeFor("json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, htmlKey,
		[]byte("<!doctype html><title>Отчёт</title><body>python.dangerous-exec"),
		storage.ContentTypeFor("html")); err != nil {
		t.Fatal(err)
	}

	report, err := r.UpsertScanReport(ctx, domain.ScanReport{
		RequestItemID: item.ID, PackageVersionID: ver.ID,
		StepCode: "sandbox_scan", Scanner: "sandbox (https://sandbox.test)",
		Rules: strPtr("p/default"), State: state, Threshold: "medium",
		FindingsTotal: 1, FindingsBlocking: 1, WorstSeverity: strPtr("high"),
		Detail:  strPtr("файлов просканировано: 12"),
		JSONKey: jsonKey, HTMLKey: htmlKey, Bucket: strPtr(store.Bucket()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return item.ID, report
}

func strPtr(s string) *string { return &s }

func testSlug(t *testing.T) string {
	out := make([]rune, 0, len(t.Name()))
	for _, c := range strings.ToLower(t.Name()) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}

func newServer(t *testing.T, r *repo.Repo, store storage.Store) http.Handler {
	t.Helper()
	return api.NewRouter(nil, api.Options{
		Reports: &api.ReportsHandler{Repo: r, Storage: store},
		// Маршруты отчётов закрыты проверкой токена, поэтому роутер
		// собирается вместе с ней. Проверка того, что без токена они
		// отвечают 401, — в auth_test.go.
		Auth: &api.AuthHandler{
			Auth: &api.Auth{Verifier: reportsVerifier(), Repo: r},
			Cfg:  reportsAuthCfg,
		},
	})
}

// reportsAuthCfg — доступ для тестов отчётов: включён локальный вход, поэтому
// токен выпускается без Keycloak. Роль не нужна: отчёт доступен любому
// аутентифицированному пользователю, как и сама заявка.
var reportsAuthCfg = mustReportsAuthConfig()

func mustReportsAuthConfig() *config.Config {
	env := map[string]string{
		"DATABASE_URL":       "postgres://не-используется/в-этих-тестах",
		"LOCAL_AUTH_ENABLED": "true",
		"LOCAL_AUTH_SECRET":  "секрет-тестов-отчётов",
	}
	cfg, err := config.Load(func(key string) string { return env[key] })
	if err != nil {
		panic("конфигурация тестов отчётов невалидна: " + err.Error())
	}
	return cfg
}

func reportsVerifier() *auth.Verifier {
	return auth.NewVerifier(auth.SettingsFromConfig(reportsAuthCfg), nil, nil)
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	token, _, err := reportsVerifier().IssueLocalToken(
		&domain.User{Username: "тест-читатель-отчётов", IsActive: true})
	if err != nil {
		t.Fatalf("выпуск тестового токена: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestListReports(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	store := storage.NewMemory("test")
	itemID, _ := fixture(t, r, store, "findings")

	rec := get(t, newServer(t, r, store), "/api/v1/request-items/"+itoa(itemID)+"/reports")
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d, тело = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		RequestItemID int64 `json:"request_item_id"`
		Reports       []struct {
			StepCode   string `json:"step_code"`
			StepTitle  string `json:"step_title"`
			State      string `json:"state"`
			StateTitle string `json:"state_title"`
			JSONURL    string `json:"json_url"`
			HTMLURL    string `json:"html_url"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	if len(payload.Reports) != 1 {
		t.Fatalf("отчётов = %d", len(payload.Reports))
	}
	got := payload.Reports[0]
	if got.StepCode != "sandbox_scan" || got.StepTitle != "Проверка в песочнице" {
		t.Errorf("шаг = %+v", got)
	}
	// Ссылки относительные и сразу пригодны для UI; ключ хранилища наружу не
	// уходит.
	if !strings.HasSuffix(got.JSONURL, "/reports/sandbox_scan.json") {
		t.Errorf("JSONURL = %q", got.JSONURL)
	}
	if strings.Contains(rec.Body.String(), "reports/"+itoa(itemID)+"/sandbox_scan.json") {
		t.Error("ключ объекта в хранилище утёк в ответ API")
	}
}

// TestUnavailableStateIsExplicit — «проверка не выполнена» в списке не должна
// читаться как «чисто».
func TestUnavailableStateIsExplicit(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	store := storage.NewMemory("test")
	itemID, _ := fixture(t, r, store, "unavailable")

	rec := get(t, newServer(t, r, store), "/api/v1/request-items/"+itoa(itemID)+"/reports")
	body := rec.Body.String()
	if !strings.Contains(body, "Проверка не выполнена") {
		t.Errorf("тело = %s — состояние unavailable не объяснено", body)
	}
	if strings.Contains(body, "Срабатываний нет") {
		t.Error("несостоявшийся прогон показан как чистый")
	}
}

func TestDownloadJSONAndHTML(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	store := storage.NewMemory("test")
	itemID, _ := fixture(t, r, store, "findings")
	h := newServer(t, r, store)

	jsonRec := get(t, h, "/api/v1/request-items/"+itoa(itemID)+"/reports/sandbox_scan.json")
	if jsonRec.Code != http.StatusOK {
		t.Fatalf("json: код = %d", jsonRec.Code)
	}
	if ct := jsonRec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("json: Content-Type = %q", ct)
	}
	if !strings.Contains(jsonRec.Body.String(), "moderation.scan-report/v1") {
		t.Errorf("json: тело = %s", jsonRec.Body.String())
	}
	// Кириллица доезжает как есть.
	if !strings.Contains(jsonRec.Body.String(), "кириллица") {
		t.Error("json: кириллица искажена по дороге")
	}

	htmlRec := get(t, h, "/api/v1/request-items/"+itoa(itemID)+"/reports/sandbox_scan.html")
	if htmlRec.Code != http.StatusOK {
		t.Fatalf("html: код = %d", htmlRec.Code)
	}
	if ct := htmlRec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("html: Content-Type = %q — браузер предложит скачать вместо показа", ct)
	}
	// inline, а не attachment: отчёт должен открываться в браузере.
	if cd := htmlRec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "inline") {
		t.Errorf("html: Content-Disposition = %q", cd)
	}
	if htmlRec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("html: нет nosniff — браузер волен угадать тип содержимого пакета")
	}
	if !strings.Contains(htmlRec.Body.String(), "python.dangerous-exec") {
		t.Error("html: содержимое отчёта не отдано")
	}
}

// TestMissingReportIsExplicit404 — отличать «прогона не было» от «файл
// потерялся» важно: первое нормально, второе — авария хранилища.
func TestMissingReportIsExplicit404(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	store := storage.NewMemory("test")
	itemID, _ := fixture(t, r, store, "findings")

	rec := get(t, newServer(t, r, store), "/api/v1/request-items/"+itoa(itemID)+"/reports/banner_scan.json")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "прогон сканера не выполнялся") {
		t.Errorf("тело = %s", rec.Body.String())
	}
}

func TestMissingFileInStorage(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	store := storage.NewMemory("test")
	itemID, report := fixture(t, r, store, "findings")
	// Файл вычищен из хранилища, строка отчёта осталась.
	if err := store.Delete(context.Background(), report.JSONKey); err != nil {
		t.Fatal(err)
	}

	rec := get(t, newServer(t, r, store), "/api/v1/request-items/"+itoa(itemID)+"/reports/sandbox_scan.json")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "вычищен") {
		t.Errorf("тело = %s — не отличает потерянный файл от невыполненного прогона", rec.Body.String())
	}
}

// TestUnknownFileNameRejected — код шага и формат уходят в ключ объекта,
// принимать сюда произвольную строку из URL нельзя.
func TestUnknownFileNameRejected(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	store := storage.NewMemory("test")
	itemID, _ := fixture(t, r, store, "findings")
	h := newServer(t, r, store)

	for _, name := range []string{
		"sandbox_scan.txt", "../../etc/passwd", "sandbox_scan", "vuln_scan.json", "sandbox_scan.json.bak",
	} {
		rec := get(t, h, "/api/v1/request-items/"+itoa(itemID)+"/reports/"+name)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMovedPermanently {
			t.Errorf("имя %q дало код %d, ожидался отказ", name, rec.Code)
		}
	}
}

func TestBadItemID(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	store := storage.NewMemory("test")

	rec := get(t, newServer(t, r, store), "/api/v1/request-items/не-число/reports")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("код = %d, ожидался 400", rec.Code)
	}
}

// TestHealthStillWorksWithoutReports — сервис обязан подниматься и без
// хранилища отчётов, отдавая health, а не падать на старте.
func TestHealthStillWorksWithoutReports(t *testing.T) {
	h := api.NewRouter(nil)
	rec := get(t, h, "/health")
	if rec.Code != http.StatusOK {
		t.Errorf("health = %d", rec.Code)
	}
	rec = get(t, h, "/api/v1/request-items/1/reports")
	if rec.Code != http.StatusNotFound {
		t.Errorf("маршрут отчётов подключён без обработчика: %d", rec.Code)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
