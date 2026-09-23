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
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/policy"
	"moderation/internal/queue"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// Решения ролей — на настоящем Postgres: их суть в том, что происходит со
// строками (снятие блокировки, распространение на другие заявки, возврат в
// очередь), а не в форме ответа.

type decisionFixture struct {
	router    http.Handler
	repo      *repo.Repo
	verifier  *auth.Verifier
	user      *domain.User
	itemID    int64
	siblingID int64
	versionID int64
	requestID int64
	policies  *policy.Holder
}

// newDecisionFixture заводит ДВЕ заявки на одну версию пакета: решение
// принимается по версии, и распространение на соседей — то, что обязательно
// нужно проверять на настоящих строках.
func newDecisionFixture(t *testing.T, itemStatus string, steps map[string]string) *decisionFixture {
	t.Helper()
	r, cleanup := mustRepo(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	slug := fmt.Sprintf("%s-%d", testSlug(t), time.Now().UnixNano())

	user, err := r.GetOrCreateUser(ctx, "решающий-"+slug, "Решающий")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := r.GetOrCreatePackage(ctx, "pypi", "dec-"+slug, "Dec-"+slug)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	mkItem := func() int64 {
		req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
			AuthorID: user.ID, Manager: "pypi", Status: "pending", Source: "ui", Warnings: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		item, err := r.CreateRequestItem(ctx, domain.RequestItem{
			RequestID: req.ID, PackageVersionID: ver.ID,
			RequestedName: pkg.DisplayName, RequestedVersion: "1.0.0",
			DependencyKind: "direct", Status: itemStatus,
		})
		if err != nil {
			t.Fatal(err)
		}
		for code, result := range steps {
			if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
				RequestItemID: item.ID, StepCode: code, StepOrder: domain.StepOrder[code],
				Result: result,
			}); err != nil {
				t.Fatal(err)
			}
		}
		return item.ID
	}
	itemID := mkItem()
	siblingID := mkItem()

	item, err := r.GetRequestItem(ctx, itemID)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"DATABASE_URL": "postgres://не-используется", "LOCAL_AUTH_ENABLED": "true",
			"LOCAL_AUTH_SECRET": "секрет-решений",
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	q := queue.New(r.Pool(), time.Minute)
	verifier := auth.NewVerifier(auth.SettingsFromConfig(cfg), nil, nil)

	service := &decisions.Service{
		Repo: r,
		Resume: func(ctx context.Context, item *domain.RequestItem, fromStep string) error {
			return q.Enqueue(ctx, item.ID, fromStep)
		},
	}
	// Справочник лицензий — настоящий, из репозитория: заявление лицензии
	// проверяет SPDX по нему, и подставной справочник проверял бы не то.
	policies := policy.NewHolder(
		"../../../config/blacklist.yml", "../../../config/licenses.yml")
	handler := &api.DecisionsHandler{Repo: r, Decisions: service, Policies: policies}

	return &decisionFixture{
		router: api.NewRouter(nil, api.Options{
			Auth:      &api.AuthHandler{Auth: &api.Auth{Verifier: verifier, Repo: r}, Cfg: cfg},
			Decisions: handler,
			// Отзыв пакета живёт в маршрутах базы пакетов, но ходит в тот же
			// сервис решений — проверять его надо тем же окружением.
			Packages: &api.PackagesHandler{
				Repo: r, Registry: registry.New(registry.Config{}), Cfg: cfg,
				Decisions: service,
			},
		}),
		repo: r, verifier: verifier, user: user, policies: policies,
		itemID: itemID, siblingID: siblingID, versionID: ver.ID, requestID: item.RequestID,
	}
}

// withPolicies подтверждает, что справочник лицензий прочитан: без него
// проверка SPDX пропускает что угодно, и тест, рассчитывающий на отказ,
// зеленел бы по неверной причине.
func (f *decisionFixture) withPolicies(t *testing.T) {
	t.Helper()
	if f.policies == nil {
		t.Fatal("справочник лицензий не подключён к окружению")
	}
	if licenses := f.policies.Licenses(); licenses.Failed() {
		t.Fatalf("справочник лицензий не прочитан: %s", licenses.Err)
	}
}

func (f *decisionFixture) do(t *testing.T, role, method, path, body string) *httptest.ResponseRecorder {
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

func (f *decisionFixture) item(t *testing.T, id int64) *domain.RequestItem {
	t.Helper()
	item, err := f.repo.GetRequestItem(context.Background(), id)
	if err != nil || item == nil {
		t.Fatalf("пакет #%d не прочитан: %v", id, err)
	}
	return item
}

// resumeStep — с какого шага пакет продолжит прогон.
func (f *decisionFixture) resumeStep(t *testing.T, itemID int64) string {
	t.Helper()
	var step *string
	err := f.repo.Pool().QueryRow(context.Background(),
		`SELECT resume_from_step FROM request_item WHERE id = $1`, itemID).Scan(&step)
	if err != nil {
		t.Fatalf("шаг возобновления не прочитан: %v", err)
	}
	if step == nil {
		return ""
	}
	return *step
}

func (f *decisionFixture) stepResult(t *testing.T, itemID int64, code string) string {
	t.Helper()
	steps, err := f.repo.ListStepsByItem(context.Background(), itemID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if s.StepCode == code {
			return s.Result
		}
	}
	return ""
}

// ---------------------------------------------------------------- карантин

func TestReleaseQuarantineResumesPipeline(t *testing.T) {
	f := newDecisionFixture(t, "quarantined", map[string]string{"quarantine": "warn"})

	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/quarantine/release", f.itemID), `{"comment":"проверено вручную"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	// Главное: пакет вернулся в очередь. Без этого кнопка «снять карантин»
	// отрабатывает, а проверка не продолжается — пакет стоит навсегда.
	item := f.item(t, f.itemID)
	if item.Status != "queued" {
		t.Fatalf("пакет должен вернуться в очередь, статус %q", item.Status)
	}
	if f.stepResult(t, f.itemID, "quarantine") != "pass" {
		t.Errorf("шаг карантина должен быть погашен: %q", f.stepResult(t, f.itemID, "quarantine"))
	}

	// Решение принимается по версии пакета, поэтому доходит до соседней заявки.
	if sibling := f.item(t, f.siblingID); sibling.Status != "queued" {
		t.Errorf("соседняя заявка на ту же версию тоже должна поехать: %q", sibling.Status)
	}
}

func TestReleaseQuarantineWrongStatus(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/quarantine/release", f.itemID), `{}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("пакет не в карантине — ожидался 409, получено %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------- DevSecOps

func TestSecurityApprovalResumesFromDownload(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})

	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/security-decision", f.itemID),
		`{"approve":true,"comment":"уязвимость неприменима"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	item := f.item(t, f.itemID)
	if item.Status != "queued" {
		t.Fatalf("после одобрения пакет должен вернуться в очередь: %q", item.Status)
	}
	// Возобновление идёт с шага скачивания: артефакт после публикации
	// вычищается, и начинать с проверки наличия в базе бессмысленно.
	//
	// Отметка читается прямо из строки, а не захватом из очереди: захват
	// берёт самый старый подходящий пакет, и в общей тестовой базе это был бы
	// чужой пакет, оставшийся от другого теста.
	if step := f.resumeStep(t, f.itemID); step != "download" {
		t.Fatalf("возобновление с шага %q, ожидался download", step)
	}

	// Разрешение DevSecOps записывается на версию: иначе возобновлённый
	// прогон снова упрётся в тот же вердикт и зациклится.
	version, err := f.repo.GetPackageVersion(context.Background(), f.versionID)
	if err != nil {
		t.Fatal(err)
	}
	if version.SecurityOverrideAt == nil {
		t.Error("решение DevSecOps должно быть записано на версию пакета")
	}
}

func TestSecurityRejectionRequiresComment(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/security-decision", f.itemID), `{"approve":false}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("отклонение без причины — ожидался 422, получено %d: %s", rec.Code, rec.Body.String())
	}
	if f.item(t, f.itemID).Status != "awaiting_security" {
		t.Error("неудачное решение не должно менять состояние пакета")
	}
}

func TestSecurityRejectionStopsPipeline(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/security-decision", f.itemID),
		`{"approve":false,"comment":"эксплуатируется в дикой природе"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if status := f.item(t, f.itemID).Status; status != "rejected" {
		t.Fatalf("отклонённый пакет: %q", status)
	}
	// Отклонение тоже доходит до соседей: иначе тот же пакет проедет через
	// другую заявку.
	if status := f.item(t, f.siblingID).Status; status != "rejected" {
		t.Errorf("соседняя заявка: %q", status)
	}
}

// Роль проверяется в API: юрист не принимает решения DevSecOps.
func TestDecisionRoleGuard(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	cases := []struct {
		role   string
		status int
	}{
		{"devsecops", http.StatusOK},
		{"legal", http.StatusForbidden},
		{"developer", http.StatusForbidden},
	}
	for _, tc := range cases {
		f := f
		if tc.status == http.StatusOK {
			// Успешный случай меняет состояние, поэтому берём свежую фикстуру.
			f = newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})
		}
		rec := f.do(t, tc.role, http.MethodPost,
			fmt.Sprintf("/api/v1/items/%d/security-decision", f.itemID),
			`{"approve":true,"comment":"ок"}`)
		if rec.Code != tc.status {
			t.Errorf("роль %s: код %d, ожидался %d", tc.role, rec.Code, tc.status)
		}
	}
}

// ---------------------------------------------------------------- лицензии

func (f *decisionFixture) claim(t *testing.T) int64 {
	t.Helper()
	spdx := "MIT"
	snapshot := "MIT License\n\nPermission is hereby granted..."
	now := time.Now().UTC()
	row, err := f.repo.CreateLicenseClaim(context.Background(), domain.LicenseClaim{
		PackageVersionID: f.versionID, RequestItemID: &f.itemID, ClaimedByID: f.user.ID,
		URL: "https://example.com/LICENSE", SPDXID: &spdx,
		SnapshotText: &snapshot, SnapshotFetchedAt: &now,
	})
	if err != nil {
		t.Fatalf("заявление: %v", err)
	}
	return row.Claim.ID
}

func TestLicenseApprovalResumesPipeline(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_legal", map[string]string{"license": "warn"})
	claimID := f.claim(t)

	rec := f.do(t, "legal", http.MethodPost,
		fmt.Sprintf("/api/v1/license-claims/%d/decision", claimID),
		`{"approve":true,"comment":"MIT подтверждена"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	payload := decodeObject(t, rec)
	if payload["status"] != "approved" || payload["decided_by"] != f.user.Username {
		t.Fatalf("заявление после решения: %v", payload)
	}

	if status := f.item(t, f.itemID).Status; status != "queued" {
		t.Fatalf("после решения юриста пакет должен вернуться в очередь: %q", status)
	}
	if f.stepResult(t, f.itemID, "license") != "pass" {
		t.Errorf("шаг лицензии должен быть погашен")
	}
	// Подтверждённая лицензия предлагается для других версий того же пакета.
	if spdx, _, err := f.repo.SuggestedLicense(context.Background(), f.versionID); err != nil || spdx != "MIT" {
		t.Errorf("подтверждённая лицензия пакета: %q (%v)", spdx, err)
	}
}

// Второе решение по тому же заявлению — конфликт, а не тихое применение
// поверх чужого.
func TestLicenseDecisionTwiceIsConflict(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_legal", map[string]string{"license": "warn"})
	claimID := f.claim(t)
	path := fmt.Sprintf("/api/v1/license-claims/%d/decision", claimID)

	if rec := f.do(t, "legal", http.MethodPost, path, `{"approve":true}`); rec.Code != http.StatusOK {
		t.Fatalf("первое решение: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.do(t, "legal", http.MethodPost, path, `{"approve":false,"comment":"передумал"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("повторное решение: код %d, ожидался 409", rec.Code)
	}
}

func TestLicenseClaimsVisibility(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_legal", map[string]string{"license": "warn"})
	claimID := f.claim(t)

	// Юрист видит все нерешённые заявления.
	list := decodeArray(t, f.do(t, "legal", http.MethodGet, "/api/v1/license-claims", ""))
	found := false
	for _, raw := range list {
		if row, ok := raw.(map[string]any); ok && row["id"] == float64(claimID) {
			found = true
			if row["snapshot_text"] == nil {
				t.Error("юристу нужен текст лицензии, а не только ссылка")
			}
		}
	}
	if !found {
		t.Fatal("заявление не попало в список юриста")
	}

	// Разработчик видит своё.
	one := decodeObject(t, f.do(t, "developer", http.MethodGet,
		fmt.Sprintf("/api/v1/license-claims/%d", claimID), ""))
	if one["id"] != float64(claimID) {
		t.Fatalf("автор заявления должен видеть его: %v", one)
	}
}

func TestLicenseDecisionRoleGuard(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_legal", map[string]string{"license": "warn"})
	claimID := f.claim(t)
	for _, role := range []string{"devsecops", "developer"} {
		rec := f.do(t, role, http.MethodPost,
			fmt.Sprintf("/api/v1/license-claims/%d/decision", claimID), `{"approve":true}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("роль %s не принимает решения юриста: код %d", role, rec.Code)
		}
	}
}

func TestDecisionOnMissingItem(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	rec := f.do(t, "devsecops", http.MethodPost,
		"/api/v1/items/999999999/security-decision", `{"approve":true}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код %d, ожидался 404", rec.Code)
	}
}

// Свёртка статуса заявки обязана знать про dry_run. Раньше он проваливался в
// последнюю ветку, и заявка, где все девять шагов прошли, показывалась
// «Отклонена» — по ней разработчик делал вывод, что пакет запрещён.
func TestRequestStatusHandlesDryRun(t *testing.T) {
	f := newDecisionFixture(t, "queued", nil)
	ctx := context.Background()

	// Второй пакет заводится в ТУ ЖЕ заявку: siblingID из фикстуры лежит в
	// другой заявке, а свёртка считается по одной.
	item := f.item(t, f.itemID)
	second, err := f.repo.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: item.RequestID, PackageVersionID: f.versionID,
		RequestedName: "второй", RequestedVersion: "1.0.0",
		DependencyKind: "direct", Status: "queued",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{f.itemID, second.ID} {
		if err := f.repo.UpdateRequestItemStatus(ctx, id, "dry_run", nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	status, err := f.repo.RecomputeRequestStatus(ctx, item.RequestID)
	if err != nil {
		t.Fatalf("пересчёт: %v", err)
	}
	if status != "dry_run" {
		t.Fatalf("статус заявки %q, ожидался dry_run", status)
	}

	// Смешанный случай: часть опубликована по-настоящему, часть в dry-run.
	if err := f.repo.UpdateRequestItemStatus(ctx, f.itemID, "approved", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	status, err = f.repo.RecomputeRequestStatus(ctx, item.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if status != "dry_run" {
		t.Fatalf("approved + dry_run дали %q: публикации не было не у всех, «одобрена» здесь неверно", status)
	}
}

// TestSecurityDecisionExplainsStaleSchema — решение не применилось, потому что
// в базе нет столбца очереди конвейера (не накатили миграцию 0008): ответ
// говорит именно это, а не «Решение не применено».
//
// Тест написан по живому случаю: DevSecOps не мог ни разрешить публикацию, ни
// закрыть заявку, и по ответам понять, что схема отстала от кода, было
// невозможно.
func TestSecurityDecisionExplainsStaleSchema(t *testing.T) {
	f := newDecisionFixture(t, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	ctx := context.Background()

	// Столбец возвращается сразу после теста: он нужен и очереди, и другим
	// тестам общей базы.
	if _, err := f.repo.Pool().Exec(ctx,
		`ALTER TABLE request_item DROP COLUMN resume_from_step`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := f.repo.Pool().Exec(context.Background(),
			`ALTER TABLE request_item ADD COLUMN resume_from_step VARCHAR(32)`); err != nil {
			t.Fatalf("восстановление столбца: %v", err)
		}
	}()

	rec := f.do(t, "devsecops", http.MethodPost,
		fmt.Sprintf("/api/v1/items/%d/security-decision", f.itemID),
		`{"approve":true,"comment":"проверено"}`)
	body := rec.Body.String()
	if !strings.Contains(body, "Схема базы не соответствует") {
		t.Fatalf("тело %s — ответ должен называть причину", body)
	}
	if !strings.Contains(body, "resume_from_step") {
		t.Errorf("тело %s — ответ должен называть, чего именно нет в базе", body)
	}
	if !strings.Contains(body, "schema") {
		t.Errorf("тело %s — ответ должен называть команду сверки схемы", body)
	}
}
