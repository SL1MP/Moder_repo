package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"moderation/internal/api"
	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// Маршруты чтения проверяются на настоящем Postgres: их работа — это и есть
// SQL (фильтры, права, склейки, постраничность), и на моке они проверяли бы
// только то, что мок настроен так же, как написан код.

type readFixture struct {
	router    http.Handler
	repo      *repo.Repo
	requestID int64
	itemID    int64
	versionID int64
	author    *domain.User
	outsider  *domain.User
	cfg       *config.Config
	verifier  *auth.Verifier
}

func newReadFixture(t *testing.T) *readFixture {
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

	pkg, err := r.GetOrCreatePackage(ctx, "pypi", "pkg-"+slug, "Pkg-"+slug)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "2.31.0", "2.31.0")
	if err != nil {
		t.Fatal(err)
	}
	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: author.ID, Manager: "pypi", Status: "awaiting_legal", Source: "ui",
		Reason: strPtr("нужен для сборки"), Warnings: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req.ID, PackageVersionID: ver.ID,
		RequestedName: pkg.DisplayName, RequestedVersion: "2.31.0",
		DependencyKind: "direct", Status: "awaiting_legal",
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	for _, s := range []struct{ code, result string }{
		{"db_check", "pass"}, {"blacklist", "pass"}, {"quarantine", "pass"},
		{"license", "warn"}, {"download", "pass"}, {"vuln_scan", "pass"},
	} {
		if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
			RequestItemID: item.ID, StepCode: s.code, StepOrder: domain.StepOrder[s.code],
			Result: s.result, StartedAt: &now, FinishedAt: &now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.UpsertVulnerabilities(ctx, ver.ID, []domain.Vulnerability{{
		ExternalID: "CVE-2024-0001", Score: 75, Severity: strPtr("high"),
		Summary: strPtr("Обход проверки сертификата"), FixedVersions: []string{"2.32.0"},
	}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.ReplaceCodeFindings(ctx, ver.ID, "semgrep", []domain.CodeFinding{{
		PackageVersionID: ver.ID, Scanner: "semgrep", RuleID: "python.exec-detected",
		Severity: "medium", FilePath: strPtr("pkg/a.py"), Message: strPtr("вызов exec"),
	}}); err != nil {
		t.Fatal(err)
	}

	cfg := readTestConfig(t)
	verifier := auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil)
	a := &api.Auth{Verifier: verifier, Repo: r}
	reg := registry.New(registry.Config{})

	return &readFixture{
		router: api.NewRouter(nil, api.Options{
			Auth:     &api.AuthHandler{Auth: a, Cfg: cfg},
			Packages: &api.PackagesHandler{Repo: r, Registry: reg, Cfg: cfg},
			Requests: &api.RequestsHandler{Repo: r, Registry: reg, Cfg: cfg},
		}),
		repo: r, requestID: req.ID, itemID: item.ID, versionID: ver.ID,
		author: author, outsider: outsider, cfg: cfg, verifier: verifier,
	}
}

func readTestConfig(t *testing.T) *config.Config {
	t.Helper()
	env := map[string]string{
		"DATABASE_URL":       "postgres://не-используется",
		"LOCAL_AUTH_ENABLED": "true",
		"LOCAL_AUTH_SECRET":  "секрет-тестов-чтения",
		"ARTIFACT_BASE_URL":  "https://artifactory.example.com",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("конфигурация теста невалидна: %v", err)
	}
	return cfg
}

// as выполняет запрос от имени пользователя с заданными ролями.
func (f *readFixture) as(t *testing.T, user *domain.User, roles []string, path string) *httptest.ResponseRecorder {
	t.Helper()
	acting := *user
	acting.Roles = roles
	token, _, err := f.verifier.IssueLocalToken(&acting)
	if err != nil {
		t.Fatalf("выпуск токена: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeObject(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("ответ не объект JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return out
}

func decodeArray(t *testing.T, rec *httptest.ResponseRecorder) []any {
	t.Helper()
	var out []any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("ответ не массив JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return out
}

// ---------------------------------------------------------------- /managers

func TestManagersDependencyFilesAreNeverNull(t *testing.T) {
	h := &api.PackagesHandler{Registry: registry.New(registry.Config{})}
	rec := httptest.NewRecorder()
	h.Managers(rec, httptest.NewRequest(http.MethodGet, "/api/v1/managers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	for _, raw := range decodeArray(t, rec) {
		manager := raw.(map[string]any)
		if _, ok := manager["dependency_files"].([]any); !ok {
			t.Errorf("менеджер %v: dependency_files = %#v, ожидался JSON-массив",
				manager["code"], manager["dependency_files"])
		}
	}
}

func TestManagersList(t *testing.T) {
	f := newReadFixture(t)
	rec := f.as(t, f.author, []string{"developer"}, "/api/v1/managers")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	items := decodeArray(t, rec)
	if len(items) != len(domain.ManagerCodes) {
		t.Fatalf("менеджеров получено %d, ожидалось %d — выпадающий список в интерфейсе "+
			"строится по этому ответу, и отсутствующий менеджер выбрать нельзя",
			len(items), len(domain.ManagerCodes))
	}
	// Порядок виден пользователю в выпадающем списке; обход map в Go случаен,
	// и без явного порядка список прыгал бы от запроса к запросу. Сверяем с
	// domain.ManagerCodes, а не со своим списком рядом: две копии одного
	// порядка разъезжаются при первом же новом менеджере.
	for i, code := range domain.ManagerCodes {
		manager := items[i].(map[string]any)
		got := manager["code"]
		if got != code {
			t.Fatalf("менеджер %d: %v, ожидался %s", i, got, code)
		}
		// В JSON это всегда массив, в том числе для git/files, у которых
		// список пуст. null здесь роняет страницу выбора менеджера: фронтенд
		// вызывает .join() для показа подсказки.
		if _, ok := manager["dependency_files"].([]any); !ok {
			t.Errorf("менеджер %s: dependency_files = %#v, ожидался JSON-массив",
				code, manager["dependency_files"])
		}
	}
	first := items[0].(map[string]any)
	for _, field := range []string{"code", "title", "entry_format", "dependency_files", "osv_ecosystem"} {
		if _, ok := first[field]; !ok {
			t.Errorf("в ответе нет поля %q", field)
		}
	}
}

func TestManagersListRequiresToken(t *testing.T) {
	f := newReadFixture(t)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/managers", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %d", rec.Code)
	}
}

func TestDetectManagerByFile(t *testing.T) {
	f := newReadFixture(t)
	cases := []struct{ filename, want string }{
		{"go.sum", "go"},
		{"go.mod", "go"},
		{"requirements.txt", "pypi"},
		{"requirements-dev.txt", "pypi"}, // шаблон requirements*.txt
		{"poetry.lock", "pypi"},
		{"package-lock.json", "npm"},
		{"Project.csproj", "nuget"}, // шаблон *.csproj
		{"/home/user/проект/go.sum", "go"},
	}
	for _, tc := range cases {
		t.Run(tc.filename, func(t *testing.T) {
			rec := f.as(t, f.author, []string{"developer"},
				"/api/v1/managers/detect?filename="+urlEscape(tc.filename))
			if rec.Code != http.StatusOK {
				t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
			}
			if got := decodeObject(t, rec)["manager"]; got != tc.want {
				t.Fatalf("менеджер %v, ожидался %s", got, tc.want)
			}
		})
	}

	// Чужой файл — не ошибка, а null: это подсказка интерфейсу.
	rec := f.as(t, f.author, []string{"developer"}, "/api/v1/managers/detect?filename=README.md")
	if got := decodeObject(t, rec)["manager"]; got != nil {
		t.Fatalf("для чужого файла ожидался null, получено %v", got)
	}
}

// ---------------------------------------------------------------- /packages

func TestPackageSearch(t *testing.T) {
	f := newReadFixture(t)
	pkgName := packageNameOf(t, f)

	rec := f.as(t, f.author, []string{"developer"}, "/api/v1/packages?q="+urlEscape(pkgName))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	if payload["total"] != float64(1) {
		t.Fatalf("total = %v, ожидалась одна находка", payload["total"])
	}
	items := payload["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %d", len(items))
	}
	item := items[0].(map[string]any)
	if item["version"] != "2.31.0" || item["manager"] != "pypi" {
		t.Fatalf("карточка разобрана неверно: %v", item)
	}
	vulns := item["vulnerabilities"].([]any)
	if len(vulns) != 1 || vulns[0].(map[string]any)["id"] != "CVE-2024-0001" {
		t.Fatalf("уязвимости: %v", item["vulnerabilities"])
	}
}

// Спецсимволы LIKE от пользователя не должны работать как шаблон: иначе
// поиск по «%» выдаёт всю базу, а по «_» совпадает с чем угодно.
func TestPackageSearchEscapesLikeWildcards(t *testing.T) {
	f := newReadFixture(t)
	rec := f.as(t, f.author, []string{"developer"}, "/api/v1/packages?q=%25")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if total := decodeObject(t, rec)["total"]; total != float64(0) {
		t.Fatalf("поиск по «%%» должен искать символ процента, а не всё подряд: total = %v", total)
	}
}

func TestPackageSearchLimitValidated(t *testing.T) {
	f := newReadFixture(t)
	for _, q := range []string{"limit=1000", "limit=абв", "offset=-1"} {
		rec := f.as(t, f.author, []string{"developer"}, "/api/v1/packages?"+q)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: ожидался 422, получено %d", q, rec.Code)
		}
	}
}

func TestPackageVersionCard(t *testing.T) {
	f := newReadFixture(t)
	rec := f.as(t, f.author, []string{"developer"},
		fmt.Sprintf("/api/v1/packages/%d", f.versionID))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	if payload["id"] != float64(f.versionID) {
		t.Fatalf("id = %v", payload["id"])
	}
	// Пакет ещё не одобрен — команды установки быть не должно: она вела бы в
	// репозиторий, где артефакта нет.
	if _, ok := payload["install_command"]; ok {
		t.Fatalf("у неодобренного пакета не должно быть команды установки: %v", payload["install_command"])
	}
	if payload["artifacts"] == nil || payload["vulnerabilities"] == nil {
		t.Fatalf("списки должны быть пустыми массивами, а не null: %s", rec.Body.String())
	}
}

func TestApprovedPackageHasInstallCommand(t *testing.T) {
	f := newReadFixture(t)
	if err := f.repo.UpdatePackageVersionStatus(context.Background(), f.versionID, "approved", nil); err != nil {
		t.Fatal(err)
	}
	rec := f.as(t, f.author, []string{"developer"},
		fmt.Sprintf("/api/v1/packages/%d", f.versionID))
	command, _ := decodeObject(t, rec)["install_command"].(string)
	if !strings.Contains(command, "pip install") || !strings.Contains(command, "artifactory.example.com") {
		t.Fatalf("команда установки должна вести во внутренний репозиторий: %q", command)
	}
}

func TestPackageVersionNotFound(t *testing.T) {
	f := newReadFixture(t)
	rec := f.as(t, f.author, []string{"developer"}, "/api/v1/packages/999999999")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ожидался 404, получено %d", rec.Code)
	}
}

// ---------------------------------------------------------------- /requests

func TestRequestCard(t *testing.T) {
	f := newReadFixture(t)
	rec := f.as(t, f.author, []string{"developer"},
		fmt.Sprintf("/api/v1/requests/%d", f.requestID))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	for _, field := range []string{
		"request_id", "manager", "status", "status_title", "approved", "author",
		"reason", "source", "include_transitive", "warnings", "created_at",
		"updated_at", "summary", "packages",
	} {
		if _, ok := payload[field]; !ok {
			t.Errorf("в ответе нет поля %q", field)
		}
	}
	packages := payload["packages"].([]any)
	if len(packages) != 1 {
		t.Fatalf("пакетов %d", len(packages))
	}
	pkg := packages[0].(map[string]any)

	// Шаги отдаются все, включая те, до которых прогон не дошёл: иначе в
	// карточке не видно, что ещё впереди. Число берём из domain.StepCodes, а
	// не литералом: снятие или добавление шага не должно требовать правки
	// числа в тесте, который проверяет не количество, а полноту.
	steps := pkg["steps"].([]any)
	if len(steps) != len(domain.StepCodes) {
		t.Fatalf("шагов %d, ожидалось %d", len(steps), len(domain.StepCodes))
	}
	last := steps[len(steps)-1].(map[string]any)
	if last["code"] != "publish" || last["result"] != "pending" {
		t.Fatalf("последний шаг: %v", last)
	}

	// Лицензия в warn — решение юриста не получено; это и должно быть видно
	// отдельным списком, потому что статус у пакета один, а ждать он может
	// двух решений сразу.
	pending := pkg["pending"].([]any)
	if len(pending) != 1 || pending[0] != "license" {
		t.Fatalf("pending = %v, ожидался license", pending)
	}
	if len(pkg["vulnerabilities"].([]any)) != 1 || len(pkg["code_findings"].([]any)) != 1 {
		t.Fatalf("уязвимости и находки должны попадать в карточку: %v", pkg)
	}

	summary := payload["summary"].(map[string]any)
	if summary["total"] != float64(1) || summary["awaiting_legal"] != float64(1) {
		t.Fatalf("сводка: %v", summary)
	}
	if payload["approved"] != false {
		t.Fatalf("заявка не одобрена целиком: %v", payload["approved"])
	}
}

// Разработчик видит свои заявки, но не чужие. Проверка именно в API: интерфейс
// прячет ссылку, но маршрут можно позвать и мимо него.
func TestRequestAccess(t *testing.T) {
	f := newReadFixture(t)
	path := fmt.Sprintf("/api/v1/requests/%d", f.requestID)

	if rec := f.as(t, f.author, []string{"developer"}, path); rec.Code != http.StatusOK {
		t.Fatalf("автор должен видеть свою заявку: %d", rec.Code)
	}
	if rec := f.as(t, f.outsider, []string{"developer"}, path); rec.Code != http.StatusForbidden {
		t.Fatalf("чужой разработчик не должен видеть заявку: %d", rec.Code)
	}
	for _, role := range []string{"devsecops", "legal", "admin"} {
		if rec := f.as(t, f.outsider, []string{role}, path); rec.Code != http.StatusOK {
			t.Errorf("роль %s должна видеть любую заявку: %d", role, rec.Code)
		}
	}
}

func TestRequestListScopedByRole(t *testing.T) {
	f := newReadFixture(t)

	// Чужой разработчик не видит заявку в списке вовсе.
	items := decodeArray(t, f.as(t, f.outsider, []string{"developer"}, "/api/v1/requests"))
	if containsRequest(items, f.requestID) {
		t.Fatal("чужая заявка не должна попадать в список разработчика")
	}

	// Автор — видит.
	items = decodeArray(t, f.as(t, f.author, []string{"developer"}, "/api/v1/requests"))
	if !containsRequest(items, f.requestID) {
		t.Fatal("автор должен видеть свою заявку в списке")
	}

	// DevSecOps видит чужие: иначе его очередь пуста.
	items = decodeArray(t, f.as(t, f.outsider, []string{"devsecops"}, "/api/v1/requests"))
	if !containsRequest(items, f.requestID) {
		t.Fatal("DevSecOps должен видеть чужие заявки")
	}

	// mine=true сужает выдачу даже тому, кто вправе видеть всё.
	items = decodeArray(t, f.as(t, f.outsider, []string{"devsecops"}, "/api/v1/requests?mine=true"))
	if containsRequest(items, f.requestID) {
		t.Fatal("mine=true должен оставлять только свои заявки")
	}
}

func TestRequestListCounts(t *testing.T) {
	f := newReadFixture(t)
	items := decodeArray(t, f.as(t, f.author, []string{"developer"}, "/api/v1/requests"))
	for _, raw := range items {
		row := raw.(map[string]any)
		if row["request_id"] != float64(f.requestID) {
			continue
		}
		if row["total"] != float64(1) || row["approved"] != float64(0) {
			t.Fatalf("счётчики: %v", row)
		}
		if row["author"] != f.author.Username {
			t.Fatalf("автор: %v", row["author"])
		}
		if row["status_title"] == "" || row["status_title"] == nil {
			t.Fatalf("статус должен быть с человеческим названием: %v", row)
		}
		return
	}
	t.Fatal("заявка не найдена в списке")
}

func TestRequestFilters(t *testing.T) {
	f := newReadFixture(t)
	cases := []struct {
		query string
		want  bool
	}{
		{"?status=awaiting_legal", true},
		{"?status=approved", false},
		{"?manager=pypi", true},
		{"?manager=npm", false},
	}
	for _, tc := range cases {
		items := decodeArray(t, f.as(t, f.author, []string{"developer"}, "/api/v1/requests"+tc.query))
		if got := containsRequest(items, f.requestID); got != tc.want {
			t.Errorf("%s: заявка в выдаче = %v, ожидалось %v", tc.query, got, tc.want)
		}
	}
}

func TestRequestNotFound(t *testing.T) {
	f := newReadFixture(t)
	rec := f.as(t, f.author, []string{"admin"}, "/api/v1/requests/999999999")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ожидался 404, получено %d", rec.Code)
	}
}

func containsRequest(items []any, id int64) bool {
	for _, raw := range items {
		if row, ok := raw.(map[string]any); ok && row["request_id"] == float64(id) {
			return true
		}
	}
	return false
}

func packageNameOf(t *testing.T, f *readFixture) string {
	t.Helper()
	row, err := f.repo.GetVersionRow(context.Background(), f.versionID)
	if err != nil || row == nil {
		t.Fatalf("версия не прочитана: %v", err)
	}
	return row.Name
}

func urlEscape(v string) string { return url.QueryEscape(v) }
