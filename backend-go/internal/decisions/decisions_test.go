package decisions_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/db"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/pipeline"
	"moderation/internal/repo"
)

// Тесты распространения решений на siblings — ПЕРВОЕ, что должно быть покрыто
// при переносе (прямое указание docs/migration-to-go.md). Поведение незаметно
// для тестов, написанных «по одной заявке за раз»: решение в одной заявке
// выглядит корректным, а одинаковый пакет в чужой заявке молча висит
// заблокированным навсегда.

var testPool *pgxpool.Pool

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
	testPool = pool
	return repo.New(pool), func() { pool.Close() }
}

// resumeRecorder — подставное возобновление конвейера: запоминает, кого и с
// какого шага возобновили, и переводит пакет в «проверяется».
//
// Настоящий конвейер здесь не нужен и вреден: проверяется именно то, ДО КОГО
// доведено решение, а не что конвейер потом насчитает.
type resumeRecorder struct {
	calls []resumeCall
	r     *repo.Repo
}

type resumeCall struct {
	itemID   int64
	fromStep string
}

func (rr *resumeRecorder) resume(ctx context.Context, item *domain.RequestItem, fromStep string) error {
	rr.calls = append(rr.calls, resumeCall{itemID: item.ID, fromStep: fromStep})
	return rr.r.UpdateRequestItemStatus(ctx, item.ID, "running", &fromStep, nil, nil, nil)
}

func (rr *resumeRecorder) resumedFrom(itemID int64) (string, bool) {
	for _, call := range rr.calls {
		if call.itemID == itemID {
			return call.fromStep, true
		}
	}
	return "", false
}

// fixture — одна версия пакета, заказанная в ДВУХ заявках разными людьми.
// Ровно та ситуация, ради которой существует распространение на siblings.
type fixture struct {
	version *domain.PackageVersion
	pkg     *domain.Package
	first   *domain.RequestItem // из этой заявки приходит решение
	second  *domain.RequestItem // эта не должна остаться заблокированной
}

func setupTwoRequests(t *testing.T, r *repo.Repo, status string, openSteps map[string]string) fixture {
	t.Helper()
	ctx := context.Background()

	name := "shared-" + testSlug(t)
	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatalf("GetOrCreatePackage: %v", err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatalf("CreatePackageVersion: %v", err)
	}
	// База между прогонами не пересоздаётся — сбрасываем фикстуру.
	if _, err := testPool.Exec(ctx, `DELETE FROM request_item WHERE package_version_id = $1`, ver.ID); err != nil {
		t.Fatalf("сброс фикстуры: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE package_version SET status='new', status_reason=NULL,
		security_override_at=NULL, security_override_by_id=NULL, security_override_comment=NULL,
		quarantine_until=NULL, license_spdx=NULL, license_source=NULL WHERE id=$1`, ver.ID); err != nil {
		t.Fatalf("сброс версии: %v", err)
	}

	items := make([]*domain.RequestItem, 0, 2)
	for i, author := range []string{"dev.ivanov", "dev.sidorov"} {
		user, err := r.GetOrCreateUser(ctx, author+"-"+testSlug(t), author)
		if err != nil {
			t.Fatalf("GetOrCreateUser: %v", err)
		}
		req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
			AuthorID: user.ID, Manager: "pypi", Status: "pending", Source: "ui",
		})
		if err != nil {
			t.Fatalf("CreateModerationRequest: %v", err)
		}
		item, err := r.CreateRequestItem(ctx, domain.RequestItem{
			RequestID: req.ID, PackageVersionID: ver.ID,
			RequestedName: name, RequestedVersion: "1.0.0",
			DependencyKind: "direct", Status: status,
		})
		if err != nil {
			t.Fatalf("CreateRequestItem: %v", err)
		}
		// Открытые шаги — то, что конвейер оставил бы непогашенным.
		for code, result := range openSteps {
			if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
				RequestItemID: item.ID, StepCode: code,
				StepOrder: domain.StepOrder[code], Result: result,
			}); err != nil {
				t.Fatalf("UpsertPipelineStep: %v", err)
			}
		}
		items = append(items, item)
		_ = i
	}
	return fixture{version: ver, pkg: pkg, first: items[0], second: items[1]}
}

func newService(r *repo.Repo) (*decisions.Service, *resumeRecorder) {
	rec := &resumeRecorder{r: r}
	return &decisions.Service{
		Repo: r, Resume: rec.resume,
		Now: func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) },
	}, rec
}

func stepResult(t *testing.T, r *repo.Repo, itemID int64, code string) string {
	t.Helper()
	steps, err := r.ListStepsByItem(context.Background(), itemID)
	if err != nil {
		t.Fatalf("ListStepsByItem: %v", err)
	}
	for _, s := range steps {
		if s.StepCode == code {
			return s.Result
		}
	}
	return ""
}

func itemStatus(t *testing.T, r *repo.Repo, itemID int64) string {
	t.Helper()
	item, err := r.GetRequestItem(context.Background(), itemID)
	if err != nil {
		t.Fatalf("GetRequestItem: %v", err)
	}
	return item.Status
}

func testSlug(t *testing.T) string {
	out := make([]rune, 0, len(t.Name()))
	for _, c := range t.Name() {
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// --------------------------------------------------------------------- DevSecOps

// TestSecurityApprovalReachesSiblings — центральный тест пакета. Апрув в одной
// заявке обязан разблокировать тот же пакет в чужой.
func TestSecurityApprovalReachesSiblings(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "awaiting_security", map[string]string{
		"vuln_scan": "fail", "sandbox_scan": "fail",
	})
	svc, rec := newService(r)

	actor, err := r.GetOrCreateUser(ctx, "sec.petrov-"+testSlug(t), "Пётр Петров")
	if err != nil {
		t.Fatal(err)
	}

	res, err := svc.DecideSecurity(ctx, f.first, true, actor.ID, "Проверено вручную")
	if err != nil {
		t.Fatalf("DecideSecurity: %v", err)
	}

	// Чужая заявка доведена до сведения.
	if len(res.Siblings) != 1 || res.Siblings[0] != f.second.ID {
		t.Fatalf("Siblings = %v, ожидалась заявка %d — иначе чужой пакет висел бы вечно",
			res.Siblings, f.second.ID)
	}
	if from, ok := rec.resumedFrom(f.second.ID); !ok || from != "download" {
		t.Errorf("конвейер чужой заявки возобновлён с %q (ok=%v), ожидался download", from, ok)
	}

	// Одно решение DevSecOps снимает блокировки по содержимому в ОБЕИХ
	// заявках: он решает по пакету целиком, а не по каждой проверке отдельно.
	//
	// Список берём из pipeline.SecurityBlockers, а не своей копией рядом:
	// именно расхождение двух таких списков в python-версии дало KeyError в
	// бою (см. комментарий в blockers.go).
	for _, item := range []*domain.RequestItem{f.first, f.second} {
		for _, code := range pipeline.SecurityBlockers {
			if got := stepResult(t, r, item.ID, code); got != "pass" {
				t.Errorf("заявка %d, шаг %s = %q, ожидался pass", item.ID, code, got)
			}
		}
	}

	// Решение записано на версии пакета — иначе возобновлённый конвейер снова
	// упёрся бы в тот же вердикт.
	version, err := r.GetPackageVersion(ctx, f.version.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version.SecurityOverrideAt == nil || version.SecurityOverrideByID == nil {
		t.Fatal("разрешение не зафиксировано на версии пакета")
	}
	if *version.SecurityOverrideByID != actor.ID {
		t.Errorf("SecurityOverrideByID = %d, ожидался %d", *version.SecurityOverrideByID, actor.ID)
	}
}

// TestSecurityRejectionReachesSiblings — отклонение тоже относится ко всем.
func TestSecurityRejectionReachesSiblings(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "awaiting_security", map[string]string{"vuln_scan": "fail"})
	svc, _ := newService(r)
	actor, _ := r.GetOrCreateUser(ctx, "sec-"+testSlug(t), "DevSecOps")

	res, err := svc.DecideSecurity(ctx, f.first, false, actor.ID, "Критическая уязвимость без исправления")
	if err != nil {
		t.Fatalf("DecideSecurity: %v", err)
	}
	if len(res.Siblings) != 1 {
		t.Fatalf("Siblings = %v", res.Siblings)
	}
	for _, id := range []int64{f.first.ID, f.second.ID} {
		if got := itemStatus(t, r, id); got != "rejected" {
			t.Errorf("заявка %d = %q, ожидался rejected", id, got)
		}
	}
	version, err := r.GetPackageVersion(ctx, f.version.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version.Status != "rejected" {
		t.Errorf("статус версии = %q", version.Status)
	}
}

// TestSecurityRejectionRequiresComment — отклонение без объяснения бесполезно
// разработчику.
func TestSecurityRejectionRequiresComment(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()

	f := setupTwoRequests(t, r, "awaiting_security", map[string]string{"vuln_scan": "fail"})
	svc, _ := newService(r)

	_, err := svc.DecideSecurity(context.Background(), f.first, false, 0, "   ")
	if !errors.Is(err, decisions.ErrValidation) {
		t.Errorf("err = %v, ожидалась ErrValidation", err)
	}
}

func TestSecurityWrongStatusIsConflict(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()

	f := setupTwoRequests(t, r, "awaiting_legal", map[string]string{"license": "warn"})
	svc, _ := newService(r)

	_, err := svc.DecideSecurity(context.Background(), f.first, true, 0, "")
	if !errors.Is(err, decisions.ErrConflict) {
		t.Errorf("err = %v, ожидалась ErrConflict", err)
	}
}

// --------------------------------------------------------------------- юрист

// TestLicenseApprovalReachesSiblings — подтверждённая лицензия относится к
// версии пакета, а не к заявке.
func TestLicenseApprovalReachesSiblings(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "awaiting_legal", map[string]string{"license": "warn"})
	svc, rec := newService(r)
	actor, _ := r.GetOrCreateUser(ctx, "legal-"+testSlug(t), "Сидорова")

	res, err := svc.DecideLicense(ctx, f.first, true, actor.ID, "MIT", "Лицензия подтверждена по файлу LICENSE")
	if err != nil {
		t.Fatalf("DecideLicense: %v", err)
	}
	if len(res.Siblings) != 1 || res.Siblings[0] != f.second.ID {
		t.Fatalf("Siblings = %v — чужая заявка осталась бы у юриста навсегда", res.Siblings)
	}
	if from, ok := rec.resumedFrom(f.second.ID); !ok || from != "download" {
		t.Errorf("возобновление чужой заявки с %q (ok=%v)", from, ok)
	}
	for _, item := range []*domain.RequestItem{f.first, f.second} {
		if got := stepResult(t, r, item.ID, "license"); got != "pass" {
			t.Errorf("заявка %d, шаг license = %q", item.ID, got)
		}
	}

	version, err := r.GetPackageVersion(ctx, f.version.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version.LicenseSPDX == nil || *version.LicenseSPDX != "MIT" {
		t.Errorf("LicenseSPDX = %v", version.LicenseSPDX)
	}
	// Подтверждённая лицензия предлагается для других версий этого пакета.
	pkg, err := r.GetPackage(ctx, f.pkg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.ConfirmedLicenseSPDX == nil || *pkg.ConfirmedLicenseSPDX != "MIT" {
		t.Errorf("ConfirmedLicenseSPDX = %v — лицензия не предложится для других версий",
			pkg.ConfirmedLicenseSPDX)
	}
}

// TestLicenseApprovalReachesClaimedSibling — сосед может быть в статусе
// license_claimed (разработчик уже приложил ссылку), и его тоже надо сдвинуть.
func TestLicenseApprovalReachesClaimedSibling(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "awaiting_legal", map[string]string{"license": "warn"})
	if err := r.UpdateRequestItemStatus(ctx, f.second.ID, "license_claimed", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	svc, _ := newService(r)
	actor, _ := r.GetOrCreateUser(ctx, "legal2-"+testSlug(t), "Сидорова")

	res, err := svc.DecideLicense(ctx, f.first, true, actor.ID, "Apache-2.0", "")
	if err != nil {
		t.Fatalf("DecideLicense: %v", err)
	}
	if len(res.Siblings) != 1 {
		t.Fatalf("Siblings = %v, сосед в статусе license_claimed пропущен", res.Siblings)
	}
}

func TestLicenseRejectionReachesSiblings(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "awaiting_legal", map[string]string{"license": "warn"})
	svc, _ := newService(r)
	actor, _ := r.GetOrCreateUser(ctx, "legal3-"+testSlug(t), "Сидорова")

	if _, err := svc.DecideLicense(ctx, f.first, false, actor.ID, "", "GPL-3.0 несовместима с политикой"); err != nil {
		t.Fatalf("DecideLicense: %v", err)
	}
	for _, id := range []int64{f.first.ID, f.second.ID} {
		if got := itemStatus(t, r, id); got != "rejected" {
			t.Errorf("заявка %d = %q, ожидался rejected", id, got)
		}
	}
}

// --------------------------------------------------------------------- карантин

// TestQuarantineReleaseReachesSiblings — карантин снят с версии пакета,
// значит, и со всех, кто её заказал.
func TestQuarantineReleaseReachesSiblings(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "quarantined", map[string]string{"quarantine": "warn"})
	svc, rec := newService(r)

	res, err := svc.ReleaseQuarantine(ctx, f.first, true, "Пакет нужен срочно")
	if err != nil {
		t.Fatalf("ReleaseQuarantine: %v", err)
	}
	if len(res.Siblings) != 1 || res.Siblings[0] != f.second.ID {
		t.Fatalf("Siblings = %v", res.Siblings)
	}
	// Возобновление с шага лицензии: карантин повторно выполнять незачем —
	// дата публикации не изменилась.
	for _, id := range []int64{f.first.ID, f.second.ID} {
		if from, ok := rec.resumedFrom(id); !ok || from != "license" {
			t.Errorf("заявка %d возобновлена с %q (ok=%v), ожидался license", id, from, ok)
		}
		// Блокировка снята явно, иначе публикация ждала бы вечно.
		if got := stepResult(t, r, id, "quarantine"); got != "pass" {
			t.Errorf("заявка %d, шаг quarantine = %q", id, got)
		}
	}
	version, err := r.GetPackageVersion(ctx, f.version.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version.QuarantineUntil != nil {
		t.Error("срок карантина не снят с версии")
	}
}

func TestQuarantineReleaseWrongStatus(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()

	f := setupTwoRequests(t, r, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	svc, _ := newService(r)

	_, err := svc.ReleaseQuarantine(context.Background(), f.first, true, "")
	if !errors.Is(err, decisions.ErrConflict) {
		t.Errorf("err = %v, ожидалась ErrConflict", err)
	}
}

// TestQuarantineReleaseAcceptsLegacyManualStatus — до исправления ошибка
// получения метаданных записывала awaiting_security, хотя открытым шагом был
// quarantine. Уже созданные заявки должны разблокироваться после обновления,
// а не требовать ручной правки БД.
func TestQuarantineReleaseAcceptsLegacyManualStatus(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()

	f := setupTwoRequests(t, r, "awaiting_security", map[string]string{"quarantine": "warn"})
	svc, rec := newService(r)

	res, err := svc.ReleaseQuarantine(context.Background(), f.first, true, "ручная проверка")
	if err != nil {
		t.Fatalf("legacy-карантин не снят: %v", err)
	}
	if len(res.Siblings) != 1 || res.Siblings[0] != f.second.ID {
		t.Fatalf("legacy siblings = %v", res.Siblings)
	}
	for _, id := range []int64{f.first.ID, f.second.ID} {
		if got := stepResult(t, r, id, "quarantine"); got != "pass" {
			t.Errorf("заявка %d, шаг quarantine = %q, ожидался pass", id, got)
		}
		if from, ok := rec.resumedFrom(id); !ok || from != "license" {
			t.Errorf("заявка %d возобновлена с %q (ok=%v), ожидался license", id, from, ok)
		}
	}
}

// --------------------------------------------------------------------- границы

// TestSiblingsOnlyWaitingOnes — решение не должно трогать чужие заявки,
// которые уже завершены или ждут ДРУГОГО решения.
func TestSiblingsOnlyWaitingOnes(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "awaiting_security", map[string]string{"vuln_scan": "warn"})
	// Соседняя заявка уже одобрена — трогать её нельзя.
	if err := r.UpdateRequestItemStatus(ctx, f.second.ID, "approved", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	svc, rec := newService(r)
	actor, _ := r.GetOrCreateUser(ctx, "sec4-"+testSlug(t), "DevSecOps")

	res, err := svc.DecideSecurity(ctx, f.first, true, actor.ID, "ок")
	if err != nil {
		t.Fatalf("DecideSecurity: %v", err)
	}
	if len(res.Siblings) != 0 {
		t.Errorf("Siblings = %v — тронута уже завершённая заявка", res.Siblings)
	}
	if _, ok := rec.resumedFrom(f.second.ID); ok {
		t.Error("возобновлён конвейер уже одобренной заявки")
	}
	if got := itemStatus(t, r, f.second.ID); got != "approved" {
		t.Errorf("статус соседней заявки изменился на %q", got)
	}
}

// TestClearBlockerIgnoresClosedStep — повторное решение не должно «снимать»
// то, что уже снято, и уж тем более менять результат пройденного шага.
func TestClearBlockerIgnoresClosedStep(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	f := setupTwoRequests(t, r, "awaiting_security", map[string]string{
		"vuln_scan": "warn", "download": "pass",
	})
	svc, _ := newService(r)
	actor, _ := r.GetOrCreateUser(ctx, "sec5-"+testSlug(t), "DevSecOps")

	if _, err := svc.DecideSecurity(ctx, f.first, true, actor.ID, "ок"); err != nil {
		t.Fatalf("DecideSecurity: %v", err)
	}
	// Шаг скачивания как был pass, так и остался — его никто не «снимал».
	if got := stepResult(t, r, f.first.ID, "download"); got != "pass" {
		t.Errorf("download = %q, пройденный шаг не должен меняться", got)
	}
}

// TestResumeNotConfigured — забытая настройка возобновления обязана быть
// ошибкой, а не тихим «решение принято, но ничего не поехало».
func TestResumeNotConfigured(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()

	f := setupTwoRequests(t, r, "quarantined", map[string]string{"quarantine": "warn"})
	svc := &decisions.Service{Repo: r}

	if _, err := svc.ReleaseQuarantine(context.Background(), f.first, true, ""); err == nil {
		t.Error("решение принято без настроенного возобновления конвейера")
	}
}
