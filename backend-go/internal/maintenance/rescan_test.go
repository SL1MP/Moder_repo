package maintenance_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"moderation/internal/artifactstore"
	"moderation/internal/domain"
	"moderation/internal/osv"
	"moderation/internal/repo"
)

// Перепроверка — единственное место, где сервис сам отменяет ранее принятое
// решение. Ошибка в одну сторону оставляет уязвимый пакет опубликованным, в
// другую — отменяет вердикт DevSecOps при каждом обновлении базы.

// fakeIndex — база уязвимостей в памяти: пакет -> находки.
type fakeIndex struct {
	findings map[string][]osv.Finding
	queries  int
}

func (f *fakeIndex) Source() string { return "snapshot" }
func (f *fakeIndex) CurrentVersion(context.Context) (*osv.IndexVersion, error) {
	return &osv.IndexVersion{Version: "test", Source: "snapshot"}, nil
}
func (f *fakeIndex) LocalDBPath() string { return "" }

func (f *fakeIndex) Query(_ context.Context, manager, name, version string) ([]osv.Finding, error) {
	f.queries++
	return f.findings[fmt.Sprintf("%s|%s|%s", manager, name, version)], nil
}

// deletingStore — артефактори, которое помнит, что с него снимали.
type deletingStore struct {
	deleted []string
	fail    bool
}

func (d *deletingStore) Kind() string                            { return artifactstore.KindNexus }
func (d *deletingStore) DryRun() bool                            { return false }
func (d *deletingStore) ArtifactURL(artifactstore.Target) string { return "" }
func (d *deletingStore) Exists(context.Context, artifactstore.Target) (bool, error) {
	return true, nil
}
func (d *deletingStore) Publish(context.Context, artifactstore.Target, []byte) (string, error) {
	return "", nil
}
func (d *deletingStore) StatFile(context.Context, string, string) (*artifactstore.RemoteFile, error) {
	return nil, nil
}
func (d *deletingStore) ReadFile(context.Context, string, string) ([]byte, error) { return nil, nil }

// Сырые операции по путям отзыву пакета не нужны — он снимает опубликованный
// компонент, а не файл из промежуточной зоны. Реализованы минимально, чтобы
// удовлетворить контракт.
func (d *deletingStore) WriteFile(context.Context, string, string, []byte, string) error {
	return nil
}

func (d *deletingStore) DeleteFile(context.Context, string, string) (bool, error) {
	return false, nil
}

func (d *deletingStore) ListFiles(context.Context, string, string) ([]artifactstore.RemoteFile, error) {
	return nil, nil
}

func (d *deletingStore) MoveFile(context.Context, string, string, string, string) error {
	return artifactstore.ErrMoveUnsupported
}

func (d *deletingStore) Delete(_ context.Context, t artifactstore.Target) (bool, error) {
	if d.fail {
		return false, fmt.Errorf("артефактори недоступно")
	}
	d.deleted = append(d.deleted, t.Repo+"/"+t.Name+"/"+t.Version)
	return true, nil
}

// approved — одобренная версия пакета, опубликованная и заказанная заявкой.
func approvedVersion(t *testing.T, r *repo.Repo, known []domain.Vulnerability) (*domain.PackageVersion, int64, string) {
	t.Helper()
	ctx := context.Background()
	name := "res-" + slug(t)

	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatalf("GetOrCreatePackage: %v", err)
	}
	version, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatalf("CreatePackageVersion: %v", err)
	}
	if err := r.UpdatePackageVersionStatus(ctx, version.ID, "approved", nil); err != nil {
		t.Fatalf("одобрение версии: %v", err)
	}
	version.Status = "approved"

	artifact, err := r.GetOrCreateArtifact(ctx, version.ID, name+".whl")
	if err != nil {
		t.Fatalf("GetOrCreateArtifact: %v", err)
	}
	if err := r.MarkArtifactPublished(ctx, artifact.ID,
		"http://nexus:8081/repository/pypi-internal/packages/"+name+"/1.0.0/"+name+".whl",
		time.Now().UTC()); err != nil {
		t.Fatalf("MarkArtifactPublished: %v", err)
	}
	if len(known) > 0 {
		if err := r.UpsertVulnerabilities(ctx, version.ID, known, nil); err != nil {
			t.Fatalf("UpsertVulnerabilities: %v", err)
		}
	}

	user, err := r.GetOrCreateUser(ctx, "автор-"+name, "Автор")
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	request, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: user.ID, Manager: "pypi", Status: "approved", Source: "ui",
	})
	if err != nil {
		t.Fatalf("CreateModerationRequest: %v", err)
	}
	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: request.ID, PackageVersionID: version.ID,
		RequestedName: name, RequestedVersion: "1.0.0",
		DependencyKind: "direct", Status: "approved",
	})
	if err != nil {
		t.Fatalf("CreateRequestItem: %v", err)
	}
	return version, item.ID, name
}

func finding(id string, cvss float64) osv.Finding {
	return osv.Finding{ExternalID: id, CVSSScore: cvss, Severity: "high"}
}

func versionStatus(t *testing.T, r *repo.Repo, id int64) string {
	t.Helper()
	row, err := r.GetVersionRow(context.Background(), id)
	if err != nil || row == nil {
		t.Fatalf("GetVersionRow(%d): %v", id, err)
	}
	return row.Version.Status
}

// Новая уязвимость выше порога — пакет отзывается, снимается с публикации, а
// заявки, в которых он одобрен, переводятся в «отозван».
func TestRescanRevokesOnNewVulnerability(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	version, itemID, name := approvedVersion(t, r, nil)

	index := &fakeIndex{findings: map[string][]osv.Finding{
		fmt.Sprintf("pypi|%s|1.0.0", name): {finding("CVE-2026-1", 9.1)},
	}}
	store := &deletingStore{}
	service, _ := newService(t, r, newFakeStorage(), now)
	service.Artifacts = store

	result, err := service.RescanApproved(context.Background(), index, 70, nil)
	if err != nil {
		t.Fatalf("RescanApproved: %v", err)
	}
	if result.Revoked < 1 {
		t.Fatalf("отозвано пакетов: %d", result.Revoked)
	}
	if status := versionStatus(t, r, version.ID); status != "revoked" {
		t.Errorf("статус версии = %q, ожидался revoked", status)
	}
	if status := itemStatus(t, r, itemID); status != "revoked" {
		t.Errorf("статус пакета заявки = %q, ожидался revoked", status)
	}
	if len(store.deleted) == 0 {
		t.Error("пакет не снят с публикации — из него продолжат ставить")
	}
	// Репозиторий берётся из адреса публикации, а не из настроек.
	if len(store.deleted) > 0 && store.deleted[0][:len("pypi-internal/")] != "pypi-internal/" {
		t.Errorf("снимали не из того репозитория: %s", store.deleted[0])
	}
}

// Уязвимость, известная на момент одобрения, — это решение DevSecOps.
// Отзывать по ней при каждом обновлении базы значит молча отменять чужое
// решение.
func TestRescanKeepsPackageWithKnownVulnerability(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	version, itemID, name := approvedVersion(t, r, []domain.Vulnerability{{
		ExternalID: "CVE-2026-СТАРАЯ", Score: 91, Severity: strptr("high"),
	}})

	index := &fakeIndex{findings: map[string][]osv.Finding{
		fmt.Sprintf("pypi|%s|1.0.0", name): {finding("CVE-2026-СТАРАЯ", 9.1)},
	}}
	store := &deletingStore{}
	service, _ := newService(t, r, newFakeStorage(), now)
	service.Artifacts = store

	result, err := service.RescanApproved(context.Background(), index, 70, nil)
	if err != nil {
		t.Fatalf("RescanApproved: %v", err)
	}
	if result.Revoked != 0 {
		t.Fatalf("отозвано пакетов: %d, ожидалось 0", result.Revoked)
	}
	if status := versionStatus(t, r, version.ID); status != "approved" {
		t.Errorf("статус версии = %q, ожидался approved", status)
	}
	if status := itemStatus(t, r, itemID); status != "approved" {
		t.Errorf("статус пакета заявки = %q", status)
	}
	if len(store.deleted) != 0 {
		t.Error("пакет сняли с публикации по уже известной уязвимости")
	}
}

// Находка ниже порога не отзывает пакет, но обновляет максимальный балл:
// карточка обязана показывать то, что знает сегодняшняя база.
func TestRescanUpdatesScoreBelowThreshold(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	version, _, name := approvedVersion(t, r, nil)

	index := &fakeIndex{findings: map[string][]osv.Finding{
		fmt.Sprintf("pypi|%s|1.0.0", name): {finding("CVE-2026-2", 4.0)},
	}}
	service, _ := newService(t, r, newFakeStorage(), now)
	service.Artifacts = &deletingStore{}

	if _, err := service.RescanApproved(context.Background(), index, 70, nil); err != nil {
		t.Fatalf("RescanApproved: %v", err)
	}
	if status := versionStatus(t, r, version.ID); status != "approved" {
		t.Errorf("статус версии = %q, ожидался approved", status)
	}
	row, err := r.GetVersionRow(context.Background(), version.ID)
	if err != nil {
		t.Fatalf("GetVersionRow: %v", err)
	}
	if row.Version.MaxVulnScore == nil || *row.Version.MaxVulnScore != 40 {
		t.Errorf("максимальный балл = %v, ожидался 40", row.Version.MaxVulnScore)
	}
}

// Недоступное артефактори не должно оставить сервис с «одобренным» пакетом, в
// котором уже нашли дыру: статус меняется, а о неснятой копии говорится вслух.
func TestRescanRevokesEvenIfUnpublishFails(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	version, _, name := approvedVersion(t, r, nil)

	index := &fakeIndex{findings: map[string][]osv.Finding{
		fmt.Sprintf("pypi|%s|1.0.0", name): {finding("CVE-2026-3", 9.8)},
	}}
	service, _ := newService(t, r, newFakeStorage(), now)
	service.Artifacts = &deletingStore{fail: true}

	if _, err := service.RescanApproved(context.Background(), index, 70, nil); err != nil {
		t.Fatalf("RescanApproved: %v", err)
	}
	if status := versionStatus(t, r, version.ID); status != "revoked" {
		t.Errorf("статус версии = %q, ожидался revoked", status)
	}
}

// Отзыв обязан дойти до людей: автор заявки и DevSecOps узнают о нём из
// уведомлений, а не из неработающей установки.
func TestRescanNotifiesAuthorAndSecurity(t *testing.T) {
	r := mustRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, itemID, name := approvedVersion(t, r, nil)

	// DevSecOps, который должен получить уведомление.
	sec, err := r.GetOrCreateUser(ctx, "sec-"+name, "Петров")
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE "user" SET roles='["devsecops"]'::jsonb WHERE id=$1`,
		sec.ID); err != nil {
		t.Fatalf("роль: %v", err)
	}

	item, _ := r.GetRequestItem(ctx, itemID)
	request, _ := r.GetModerationRequest(ctx, item.RequestID)

	index := &fakeIndex{findings: map[string][]osv.Finding{
		fmt.Sprintf("pypi|%s|1.0.0", name): {finding("CVE-2026-4", 9.9)},
	}}
	service, _ := newService(t, r, newFakeStorage(), now)
	service.Artifacts = &deletingStore{}
	if _, err := service.RescanApproved(ctx, index, 70, nil); err != nil {
		t.Fatalf("RescanApproved: %v", err)
	}

	for who, userID := range map[string]int64{"автор": request.AuthorID, "DevSecOps": sec.ID} {
		notifications, err := r.ListNotifications(ctx, userID, false, 20)
		if err != nil {
			t.Fatalf("ListNotifications: %v", err)
		}
		found := false
		for _, n := range notifications {
			if n.Event == "package_revoked" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s не получил уведомления об отзыве", who)
		}
	}
}

// Перепроверка ходит в базу уязвимостей по каждому одобренному пакету — и
// только по одобренным.
func TestRescanSkipsNonApproved(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	version, _, _ := approvedVersion(t, r, nil)
	if err := r.UpdatePackageVersionStatus(context.Background(), version.ID, "rejected", nil); err != nil {
		t.Fatalf("смена статуса: %v", err)
	}

	index := &fakeIndex{findings: map[string][]osv.Finding{}}
	service, _ := newService(t, r, newFakeStorage(), now)
	service.Artifacts = &deletingStore{}

	if _, err := service.RescanApproved(context.Background(), index, 70, nil); err != nil {
		t.Fatalf("RescanApproved: %v", err)
	}
	if status := versionStatus(t, r, version.ID); status != "rejected" {
		t.Errorf("статус версии = %q, перепроверка не должна была его трогать", status)
	}
}

func TestRescanNeedsIndex(t *testing.T) {
	r := mustRepo(t)
	service, _ := newService(t, r, newFakeStorage(), time.Now().UTC())
	if _, err := service.RescanApproved(context.Background(), nil, 70, nil); err == nil {
		t.Fatal("без базы уязвимостей перепроверка невозможна — ожидалась ошибка")
	}
}

func strptr(v string) *string { return &v }
