package api_test

import (
	"context"
	"encoding/json"
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
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// Маршруты, доперенесённые с python-версии: POST /packages/check,
// POST /packages/{id}/revoke и POST /items/{id}/license-claim.
//
// На настоящем Postgres: суть этих маршрутов в том, что происходит со
// строками (какой статус видит разработчик, что становится с заявками при
// отзыве), а не в форме ответа.

// --------------------------------------------------------------------- check

func TestCheckReportsInstallability(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()
	slug := fmt.Sprintf("%s-%d", testSlug(t), time.Now().UnixNano())

	f := newPortedFixture(t, r)

	// Три пакета в разных состояниях плюс один, которого в базе нет.
	mkVersion(t, r, "chk-ok-"+slug, "1.0.0", "approved")
	mkVersion(t, r, "chk-run-"+slug, "2.0.0", "checking")
	mkVersion(t, r, "chk-bad-"+slug, "3.0.0", "blacklisted")

	// Четвёртая запись — корректная по формату, но такого пакета в базе нет;
	// пятая — не соответствует формату менеджера. Это разные исходы, и путать
	// их нельзя: по первому заводят заявку, по второму исправляют опечатку.
	body := fmt.Sprintf(`{"manager":"pypi","packages":[
		"chk-ok-%s==1.0.0","chk-run-%s==2.0.0","chk-bad-%s==3.0.0",
		"chk-absent-%s==9.9.9","сломанная запись без версии"]}`, slug, slug, slug, slug)
	rec := f.do(t, "developer", http.MethodPost, "/api/v1/packages/check", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		// Ключ «packages», а не «results»: контракт python-версии, который
		// читает интерфейс.
		Results []struct {
			Raw            string `json:"raw"`
			State          string `json:"state"`
			Message        string `json:"message"`
			InstallCommand string `json:"install_command"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	if len(payload.Results) != 5 {
		t.Fatalf("записей в ответе: %d, ожидалось 5", len(payload.Results))
	}

	states := make([]string, 0, 5)
	for _, item := range payload.Results {
		states = append(states, item.State)
	}
	want := []string{"approved", "in_progress", "blocked", "not_found", "invalid_format"}
	for i, state := range want {
		if states[i] != state {
			t.Errorf("запись %d: состояние %q, ожидалось %q (%v)", i, states[i], state, states)
		}
	}
	// Одобренному — готовая команда установки: ради неё проверку и открывают.
	if payload.Results[0].InstallCommand == "" {
		t.Error("для одобренного пакета не отдана команда установки")
	}
	// Заблокированному — причина и что делать дальше. «Нельзя» без
	// объяснения отправляет разработчика спрашивать в чат.
	if !strings.Contains(payload.Results[2].Message, "Подберите другую версию") {
		t.Errorf("сообщение по заблокированному: %q", payload.Results[2].Message)
	}
	// «В базе нет» и «неверный формат» — разные ответы: по первому заводят
	// заявку, по второму исправляют опечатку.
	if !strings.Contains(payload.Results[3].Message, "нужно заводить заявку") {
		t.Errorf("сообщение по отсутствующему: %q", payload.Results[3].Message)
	}
	_ = ctx
}

// TestCheckRejectsEmptyAndUnknownManager — ошибки ввода отличаются от
// состояния пакета: пустой список и неизвестный менеджер это 422, а не ответ
// с пустым результатом.
func TestCheckRejectsEmptyAndUnknownManager(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	f := newPortedFixture(t, r)

	for _, body := range []string{
		`{"manager":"pypi","packages":[]}`,
		`{"manager":"docekr","packages":["a==1"]}`,
	} {
		rec := f.do(t, "developer", http.MethodPost, "/api/v1/packages/check", body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("тело %s дало код %d, ожидался 422", body, rec.Code)
		}
	}
}

// TestCheckAcceptsStructuredEntries — запись принимается и парой полей: на
// странице «Добавить пакеты» форма с раздельными полями имени и версии.
func TestCheckAcceptsStructuredEntries(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	slug := fmt.Sprintf("%s-%d", testSlug(t), time.Now().UnixNano())
	f := newPortedFixture(t, r)
	mkVersion(t, r, "chk-struct-"+slug, "1.2.3", "approved")

	body := fmt.Sprintf(`{"manager":"pypi","packages":[{"name":"chk-struct-%s","version":"1.2.3"}]}`, slug)
	rec := f.do(t, "developer", http.MethodPost, "/api/v1/packages/check", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"approved"`) {
		t.Errorf("пакет не найден по паре полей: %s", rec.Body.String())
	}
}

// --------------------------------------------------------------------- revoke

// TestRevokeMovesAllItemsToRevoked — отзыв доходит до ВСЕХ заявок с этой
// версией, а не только до той, из которой нажали кнопку.
//
// Иначе разработчик чужой заявки продолжит ставить пакет из внутреннего
// репозитория и не узнает, почему тот вдруг перестал существовать.
func TestRevokeMovesAllItemsToRevoked(t *testing.T) {
	f := newDecisionFixture(t, "approved", map[string]string{"publish": "pass"})
	if err := f.repo.UpdatePackageVersionStatus(
		context.Background(), f.versionID, "approved", nil); err != nil {
		t.Fatal(err)
	}

	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/packages/%d/revoke", f.versionID),
		`{"reason":"найдена критическая уязвимость","unpublish":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	for _, id := range []int64{f.itemID, f.siblingID} {
		if got := f.item(t, id).Status; got != "revoked" {
			t.Errorf("пакет #%d = %q, ожидался revoked", id, got)
		}
	}
	version, err := f.repo.GetPackageVersion(context.Background(), f.versionID)
	if err != nil {
		t.Fatal(err)
	}
	if version.Status != "revoked" {
		t.Errorf("версия = %q, ожидался revoked", version.Status)
	}
}

// TestRevokeRequiresReason — отзыв без причины не принимается.
//
// Причину увидят авторы всех заявок с этой версией; без неё отзыв невозможно
// объяснить ни им, ни себе через полгода.
func TestRevokeRequiresReason(t *testing.T) {
	f := newDecisionFixture(t, "approved", map[string]string{"publish": "pass"})
	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/packages/%d/revoke", f.versionID), `{"reason":"   "}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("код %d, ожидался 422: %s", rec.Code, rec.Body.String())
	}
}

// TestRevokeForbiddenForDeveloper — отзыв отменяет ранее принятое решение и
// снимает пакет у всех сразу: это не действие разработчика.
func TestRevokeForbiddenForDeveloper(t *testing.T) {
	f := newDecisionFixture(t, "approved", map[string]string{"publish": "pass"})
	rec := f.do(t, "developer", http.MethodPost,
		fmt.Sprintf("/api/v1/packages/%d/revoke", f.versionID), `{"reason":"хочу"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403: %s", rec.Code, rec.Body.String())
	}
}

// --------------------------------------------------------------- license-claim

// TestClaimLicenseStoresSnapshot — по приложенной ссылке снимается ТЕКСТ, а не
// сохраняется одна ссылка.
//
// Ссылка через год может вести в никуда, а решение юриста принято по
// конкретному тексту, и предъявить надо именно его.
func TestClaimLicenseStoresSnapshot(t *testing.T) {
	license := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><style>.x{}</style></head><body>
			<div>MIT License</div><p>Permission is hereby granted</p></body></html>`))
	}))
	defer license.Close()

	f := newDecisionFixture(t, "awaiting_legal", map[string]string{"license": "warn"})
	f.withPolicies(t)

	rec := f.do(t, "developer", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/license-claim", f.itemID),
		fmt.Sprintf(`{"url":%q,"spdx_id":"MIT","comment":"лицензия в репозитории"}`, license.URL))
	if rec.Code != http.StatusCreated {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	claims, err := f.repo.ListLicenseClaims(context.Background(), "pending", nil)
	if err != nil {
		t.Fatal(err)
	}
	var found *repo.ClaimRow
	for i := range claims {
		if claims[i].Claim.RequestItemID != nil && *claims[i].Claim.RequestItemID == f.itemID {
			found = &claims[i]
		}
	}
	if found == nil {
		t.Fatal("заявление не записано")
	}
	if found.Claim.SnapshotText == nil {
		t.Fatal("текст лицензии не снят — юристу придётся открывать ссылку самому")
	}
	snapshot := *found.Claim.SnapshotText
	if !strings.Contains(snapshot, "MIT License") {
		t.Errorf("в снапшоте нет текста лицензии: %q", snapshot)
	}
	// Разметка и скрипты в снапшот попадать не должны: юрист читает текст.
	for _, junk := range []string{"<div>", ".x{}", "<html"} {
		if strings.Contains(snapshot, junk) {
			t.Errorf("в снапшоте осталась разметка %q", junk)
		}
	}
	// Статус пакета сменился: заявление — это событие, которого ждёт юрист.
	if got := f.item(t, f.itemID).Status; got != "license_claimed" {
		t.Errorf("статус пакета = %q, ожидался license_claimed", got)
	}
}

// TestClaimLicenseRejectsUnknownSPDX — произвольная строка вместо
// идентификатора тихо ломает автоматическую сверку лицензии на следующем
// прогоне конвейера, поэтому отвергается здесь.
func TestClaimLicenseRejectsUnknownSPDX(t *testing.T) {
	license := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("MIT License"))
	}))
	defer license.Close()

	f := newDecisionFixture(t, "awaiting_legal", map[string]string{"license": "warn"})
	f.withPolicies(t)

	rec := f.do(t, "developer", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/license-claim", f.itemID),
		fmt.Sprintf(`{"url":%q,"spdx_id":"ВЫДУМАННАЯ-1.0"}`, license.URL))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("код %d, ожидался 422: %s", rec.Code, rec.Body.String())
	}
	// Сообщение обязано подсказать, из чего выбирать: «неизвестный
	// идентификатор» без списка ничем не помогает.
	if !strings.Contains(rec.Body.String(), "справочник") {
		t.Errorf("сообщение не объясняет причину: %s", rec.Body.String())
	}
}

// TestClaimLicenseRejectsUnreachableURL — ссылка, требующая авторизации,
// юристу бесполезна: он её не откроет.
func TestClaimLicenseRejectsUnreachableURL(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer closed.Close()

	f := newDecisionFixture(t, "awaiting_legal", map[string]string{"license": "warn"})
	f.withPolicies(t)

	rec := f.do(t, "developer", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/license-claim", f.itemID),
		fmt.Sprintf(`{"url":%q}`, closed.URL))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("код %d, ожидался 422: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "без авторизации") {
		t.Errorf("сообщение не объясняет причину: %s", rec.Body.String())
	}
}

// TestClaimLicenseRefusedWhenNotWaiting — заявлять лицензию по пакету, который
// её решения не ждёт, незачем.
func TestClaimLicenseRefusedWhenNotWaiting(t *testing.T) {
	license := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("MIT License"))
	}))
	defer license.Close()

	f := newDecisionFixture(t, "approved", map[string]string{"license": "pass"})
	f.withPolicies(t)

	rec := f.do(t, "developer", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/license-claim", f.itemID),
		fmt.Sprintf(`{"url":%q}`, license.URL))
	if rec.Code != http.StatusConflict {
		t.Fatalf("код %d, ожидался 409: %s", rec.Code, rec.Body.String())
	}
}

// --------------------------------------------------------------- вспомогательное

// portedFixture — окружение маршрутов базы пакетов.
type portedFixture struct {
	router   http.Handler
	verifier *auth.Verifier
	user     *domain.User
}

func newPortedFixture(t *testing.T, r *repo.Repo) *portedFixture {
	t.Helper()
	ctx := context.Background()
	user, err := r.GetOrCreateUser(ctx,
		fmt.Sprintf("проверяющий-%d", time.Now().UnixNano()), "Проверяющий")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"DATABASE_URL": "postgres://не-используется", "LOCAL_AUTH_ENABLED": "true",
			"LOCAL_AUTH_SECRET": "секрет-проверки",
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil)
	return &portedFixture{
		router: api.NewRouter(nil, api.Options{
			Auth: &api.AuthHandler{Auth: &api.Auth{Verifier: verifier, Repo: r}, Cfg: cfg},
			Packages: &api.PackagesHandler{
				Repo: r, Registry: registry.New(registry.Config{}), Cfg: cfg,
			},
		}),
		verifier: verifier, user: user,
	}
}

func (f *portedFixture) do(t *testing.T, role, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	acting := *f.user
	acting.Roles = []string{role}
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

// mkVersion заводит пакет с версией в нужном статусе.
func mkVersion(t *testing.T, r *repo.Repo, name, version, status string) int64 {
	t.Helper()
	ctx := context.Background()
	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, version, version)
	if err != nil {
		t.Fatal(err)
	}
	if status != "new" {
		if err := r.UpdatePackageVersionStatus(ctx, ver.ID, status, nil); err != nil {
			t.Fatal(err)
		}
	}
	return ver.ID
}
