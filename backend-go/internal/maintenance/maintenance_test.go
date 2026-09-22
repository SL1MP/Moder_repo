package maintenance_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/artifactstore"
	"moderation/internal/db"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/maintenance"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

// Регламентные задачи проверяются на настоящем Postgres: вся их работа — это
// выборка по состоянию базы, и фейковый репозиторий проверял бы только то,
// что фейк написан по образу запроса.

var testPool *pgxpool.Pool

func mustRepo(t *testing.T) *repo.Repo {
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
	t.Cleanup(pool.Close)
	return repo.New(pool)
}

func slug(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", "mnt", time.Now().UnixNano())
}

// fakeStorage — временное хранилище в памяти.
type fakeStorage struct {
	objects map[string][]byte
	deleted []string
	failOn  map[string]bool
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{objects: map[string][]byte{}, failOn: map[string]bool{}}
}

func (f *fakeStorage) Bucket() string                     { return "test" }
func (f *fakeStorage) EnsureBucket(context.Context) error { return nil }
func (f *fakeStorage) Get(context.Context, string) ([]byte, error) {
	return nil, storage.ErrNotFound
}
func (f *fakeStorage) Stat(context.Context, string) (storage.Object, error) {
	return storage.Object{}, storage.ErrNotFound
}
func (f *fakeStorage) List(context.Context, string) ([]storage.Object, error) { return nil, nil }

func (f *fakeStorage) Put(_ context.Context, key string, data []byte, _ string) (storage.Object, error) {
	f.objects[key] = data
	return storage.Object{Key: key, SizeBytes: int64(len(data))}, nil
}

func (f *fakeStorage) Delete(_ context.Context, key string) error {
	if f.failOn[key] {
		return fmt.Errorf("хранилище недоступно")
	}
	delete(f.objects, key)
	f.deleted = append(f.deleted, key)
	return nil
}

// quarantined — версия в карантине, заказанная двумя заявками разных авторов.
// Две — потому что снятие карантина обязано дойти до обеих.
func quarantined(t *testing.T, r *repo.Repo, until time.Time) (*domain.RequestItem, *domain.RequestItem) {
	t.Helper()
	ctx := context.Background()
	name := "qua-" + slug(t)

	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatalf("GetOrCreatePackage: %v", err)
	}
	version, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatalf("CreatePackageVersion: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE package_version SET status='quarantined', quarantine_until=$2 WHERE id=$1`,
		version.ID, until); err != nil {
		t.Fatalf("карантин версии: %v", err)
	}

	items := make([]*domain.RequestItem, 0, 2)
	for i := 0; i < 2; i++ {
		user, err := r.GetOrCreateUser(ctx, fmt.Sprintf("автор%d-%s", i, name), "Автор")
		if err != nil {
			t.Fatalf("GetOrCreateUser: %v", err)
		}
		request, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
			AuthorID: user.ID, Manager: "pypi", Status: "quarantined", Source: "ui",
		})
		if err != nil {
			t.Fatalf("CreateModerationRequest: %v", err)
		}
		item, err := r.CreateRequestItem(ctx, domain.RequestItem{
			RequestID: request.ID, PackageVersionID: version.ID,
			RequestedName: name, RequestedVersion: "1.0.0",
			DependencyKind: "direct", Status: "quarantined",
		})
		if err != nil {
			t.Fatalf("CreateRequestItem: %v", err)
		}
		if _, err := r.UpsertPipelineStep(ctx, domain.PipelineStep{
			RequestItemID: item.ID, StepCode: "quarantine",
			StepOrder: domain.StepOrder["quarantine"], Result: "warn",
		}); err != nil {
			t.Fatalf("UpsertPipelineStep: %v", err)
		}
		items = append(items, item)
	}
	return items[0], items[1]
}

func newService(t *testing.T, r *repo.Repo, store storage.Store, now time.Time) (*maintenance.Service, *[]int64) {
	t.Helper()
	var resumed []int64
	return &maintenance.Service{
		Repo: r,
		Decisions: &decisions.Service{
			Repo: r,
			Resume: func(ctx context.Context, item *domain.RequestItem, fromStep string) error {
				resumed = append(resumed, item.ID)
				return r.UpdateRequestItemStatus(ctx, item.ID, "queued", &fromStep, nil, nil, nil)
			},
			Now: func() time.Time { return now },
		},
		Storage: store,
		Now:     func() time.Time { return now },
	}, &resumed
}

func itemStatus(t *testing.T, r *repo.Repo, id int64) string {
	t.Helper()
	item, err := r.GetRequestItem(context.Background(), id)
	if err != nil || item == nil {
		t.Fatalf("GetRequestItem(%d): %v", id, err)
	}
	return item.Status
}

// --------------------------------------------------------------- карантин

// Без этой задачи карантин — тупик: шаг ставит «в карантине до даты», и дальше
// пакет не двигается сам никогда.
func TestReleaseExpiredQuarantine(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	first, second := quarantined(t, r, now.Add(-time.Hour))

	service, resumed := newService(t, r, newFakeStorage(), now)
	if _, err := service.ReleaseExpiredQuarantine(context.Background()); err != nil {
		t.Fatalf("ReleaseExpiredQuarantine: %v", err)
	}

	// Карантин снят с ВЕРСИИ, значит и со всех, кто её заказал.
	for _, item := range []*domain.RequestItem{first, second} {
		if status := itemStatus(t, r, item.ID); status == "quarantined" {
			t.Errorf("пакет #%d остался в карантине", item.ID)
		}
	}
	// Каждый пакет возобновляется РОВНО один раз. Вторая заявка снимается
	// распространением на siblings, и если задача не перечитает её строку, то
	// снимет карантин повторно и отправит пакет в очередь второй раз.
	//
	// Считаем по своим идентификаторам, а не по общему счётчику: база между
	// прогонами не пересоздаётся, и в ней лежат пакеты соседних тестов.
	for _, item := range []*domain.RequestItem{first, second} {
		if n := countResumes(*resumed, item.ID); n != 1 {
			t.Errorf("пакет #%d возобновлён %d раз(а), ожидался ровно один", item.ID, n)
		}
	}
}

func countResumes(resumed []int64, itemID int64) int {
	n := 0
	for _, id := range resumed {
		if id == itemID {
			n++
		}
	}
	return n
}

// Срок ещё не вышел — трогать нельзя: досрочное снятие это решение DevSecOps,
// а не работа расписания.
func TestQuarantineNotYetExpiredIsLeftAlone(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	first, _ := quarantined(t, r, now.Add(48*time.Hour))

	service, _ := newService(t, r, newFakeStorage(), now)
	released, err := service.ReleaseExpiredQuarantine(context.Background())
	if err != nil {
		t.Fatalf("ReleaseExpiredQuarantine: %v", err)
	}
	if released != 0 {
		t.Fatalf("снято карантинов: %d, ожидалось 0", released)
	}
	if status := itemStatus(t, r, first.ID); status != "quarantined" {
		t.Errorf("статус пакета = %q, ожидался quarantined", status)
	}
}

// Автор заявки узнаёт о снятии карантина так же, как если бы кнопку нажал
// DevSecOps: уведомление обязано появиться.
func TestReleaseNotifiesAuthor(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	first, _ := quarantined(t, r, now.Add(-time.Hour))
	ctx := context.Background()

	item, _ := r.GetRequestItem(ctx, first.ID)
	request, _ := r.GetModerationRequest(ctx, item.RequestID)

	service, _ := newService(t, r, newFakeStorage(), now)
	if _, err := service.ReleaseExpiredQuarantine(ctx); err != nil {
		t.Fatalf("ReleaseExpiredQuarantine: %v", err)
	}

	notifications, err := r.ListNotifications(ctx, request.AuthorID, false, 20)
	if err != nil {
		t.Fatalf("ListNotifications: %v", err)
	}
	found := false
	for _, n := range notifications {
		if n.Event == "quarantine_released" {
			found = true
			if n.Title == "" {
				t.Error("у уведомления пустой заголовок")
			}
		}
	}
	if !found {
		t.Fatalf("уведомления о снятии карантина нет: %+v", notifications)
	}
}

// Работа расписания должна быть отличима от нажатой кнопки.
func TestReleaseWritesAuditFromTask(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	first, _ := quarantined(t, r, now.Add(-time.Hour))

	service, _ := newService(t, r, newFakeStorage(), now)
	if _, err := service.ReleaseExpiredQuarantine(context.Background()); err != nil {
		t.Fatalf("ReleaseExpiredQuarantine: %v", err)
	}

	// Запись ищем по своему пакету: база общая, и «последняя запись с таким
	// действием» нашлась бы от соседнего теста даже при сломанном журнале.
	var source, actor string
	err := testPool.QueryRow(context.Background(),
		`SELECT source, actor_name FROM audit_log
		 WHERE action='quarantine_released' AND entity_type='request_item' AND entity_id=$1`,
		fmt.Sprint(first.ID)).Scan(&source, &actor)
	if err != nil {
		t.Fatalf("записи о снятии карантина по пакету #%d нет: %v", first.ID, err)
	}
	if source != "task" {
		t.Errorf("источник записи = %q, ожидался task", source)
	}
	if actor == "" {
		t.Error("в журнале не указано, кто снял карантин")
	}
}

// --------------------------------------------------------------- уборка

func artifactWithObject(t *testing.T, r *repo.Repo, store *fakeStorage, uploadedAt time.Time, status string) domain.Artifact {
	t.Helper()
	ctx := context.Background()
	name := "orph-" + slug(t)

	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatalf("GetOrCreatePackage: %v", err)
	}
	version, err := r.CreatePackageVersion(ctx, pkg.ID, "1.0.0", "1.0.0")
	if err != nil {
		t.Fatalf("CreatePackageVersion: %v", err)
	}
	key := storage.ArtifactKey("pypi", name, "1.0.0", name+".whl")
	if _, err := store.Put(ctx, key, []byte("байты"), "application/octet-stream"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var id int64
	err = testPool.QueryRow(ctx, `
		INSERT INTO artifact (package_version_id, filename, s3_bucket, s3_key, s3_uploaded_at, status)
		VALUES ($1, $2, 'test', $3, $4, $5) RETURNING id`,
		version.ID, name+".whl", key, uploadedAt, status).Scan(&id)
	if err != nil {
		t.Fatalf("вставка артефакта: %v", err)
	}
	return domain.Artifact{ID: id, S3Key: &key, Status: status}
}

// Карантинная зона временная по замыслу: если её не убирать, место кончится
// в самый неудобный момент.
func TestCleanupRemovesStaleObjects(t *testing.T) {
	r := mustRepo(t)
	store := newFakeStorage()
	now := time.Now().UTC()

	stale := artifactWithObject(t, r, store, now.Add(-48*time.Hour), "downloaded")
	fresh := artifactWithObject(t, r, store, now.Add(-time.Hour), "downloaded")

	service, _ := newService(t, r, store, now)
	removed, err := service.CleanupOrphanObjects(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatalf("CleanupOrphanObjects: %v", err)
	}
	if removed < 1 {
		t.Fatalf("удалено объектов: %d", removed)
	}
	if _, ok := store.objects[*stale.S3Key]; ok {
		t.Error("зависший объект остался в хранилище")
	}
	if _, ok := store.objects[*fresh.S3Key]; !ok {
		t.Error("свежий объект удалён — срок жизни не соблюдён")
	}

	var deletedAt *time.Time
	var status string
	if err := testPool.QueryRow(context.Background(),
		`SELECT s3_deleted_at, status FROM artifact WHERE id=$1`, stale.ID).Scan(&deletedAt, &status); err != nil {
		t.Fatalf("чтение артефакта: %v", err)
	}
	if deletedAt == nil {
		t.Error("артефакт не помечен удалённым — задача придёт за ним снова")
	}
	if status != "purged" {
		t.Errorf("статус артефакта = %q, ожидался purged", status)
	}
}

// Опубликованный артефакт тоже убирается из временного хранилища, но статус у
// него уже финальный — затирать его нельзя.
func TestCleanupKeepsPublishedStatus(t *testing.T) {
	r := mustRepo(t)
	store := newFakeStorage()
	now := time.Now().UTC()
	published := artifactWithObject(t, r, store, now.Add(-48*time.Hour), "published")

	service, _ := newService(t, r, store, now)
	if _, err := service.CleanupOrphanObjects(context.Background(), 24*time.Hour); err != nil {
		t.Fatalf("CleanupOrphanObjects: %v", err)
	}
	var status string
	if err := testPool.QueryRow(context.Background(),
		`SELECT status FROM artifact WHERE id=$1`, published.ID).Scan(&status); err != nil {
		t.Fatalf("чтение артефакта: %v", err)
	}
	if status != "published" {
		t.Errorf("статус артефакта = %q, ожидался published", status)
	}
}

// Недоступное хранилище не должно превращать уборку в вечный цикл по одному и
// тому же объекту.
func TestCleanupMarksRowEvenWhenStorageFails(t *testing.T) {
	r := mustRepo(t)
	store := newFakeStorage()
	now := time.Now().UTC()
	stale := artifactWithObject(t, r, store, now.Add(-48*time.Hour), "downloaded")
	store.failOn[*stale.S3Key] = true

	service, _ := newService(t, r, store, now)
	removed, err := service.CleanupOrphanObjects(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatalf("CleanupOrphanObjects: %v", err)
	}
	if removed != 0 {
		t.Errorf("удалено объектов: %d, хранилище отвечало ошибкой", removed)
	}
	var deletedAt *time.Time
	if err := testPool.QueryRow(context.Background(),
		`SELECT s3_deleted_at FROM artifact WHERE id=$1`, stale.ID).Scan(&deletedAt); err != nil {
		t.Fatalf("чтение артефакта: %v", err)
	}
	if deletedAt == nil {
		t.Error("строка не помечена — задача будет биться об этот объект вечно")
	}
}

func TestCleanupRequiresTTL(t *testing.T) {
	r := mustRepo(t)
	service, _ := newService(t, r, newFakeStorage(), time.Now().UTC())
	if _, err := service.CleanupOrphanObjects(context.Background(), 0); err == nil {
		t.Fatal("нулевой срок жизни — это ошибка настройки, а не «удалить всё»")
	}
}

// --------------------------------------------------------------- снапшот OSV

// fakeArtifacts — артефактори с одним файлом: снапшотом.
type fakeArtifacts struct {
	payload  []byte
	checksum string
	modified time.Time
	reads    int
}

func (f *fakeArtifacts) Kind() string                            { return artifactstore.KindNexus }
func (f *fakeArtifacts) DryRun() bool                            { return false }
func (f *fakeArtifacts) ArtifactURL(artifactstore.Target) string { return "" }
func (f *fakeArtifacts) Exists(context.Context, artifactstore.Target) (bool, error) {
	return false, nil
}
func (f *fakeArtifacts) Publish(context.Context, artifactstore.Target, []byte) (string, error) {
	return "", nil
}
func (f *fakeArtifacts) Delete(context.Context, artifactstore.Target) (bool, error) {
	return false, nil
}

func (f *fakeArtifacts) StatFile(context.Context, string, string) (*artifactstore.RemoteFile, error) {
	return &artifactstore.RemoteFile{
		Checksum: f.checksum, LastModified: f.modified, SizeBytes: int64(len(f.payload)),
	}, nil
}

func (f *fakeArtifacts) ReadFile(context.Context, string, string) ([]byte, error) {
	f.reads++
	return f.payload, nil
}

func snapshotArchive(t *testing.T) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("PyPI/GHSA-" + slug(t) + ".json")
	if err != nil {
		t.Fatalf("сборка архива: %v", err)
	}
	record := `{"id":"GHSA-TEST","summary":"тест","affected":[{"package":{"ecosystem":"PyPI",` +
		`"name":"requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},` +
		`{"fixed":"2.32.0"}]}]}]}`
	if _, err := w.Write([]byte(record)); err != nil {
		t.Fatalf("запись в архив: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("закрытие архива: %v", err)
	}
	digest := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(digest[:])
}

// Версия снапшота фиксируется в базе: по ней видно, чем именно проверяли
// пакет, и её же показывает экран «Настройка».
func TestSyncOSVSnapshotRecordsVersion(t *testing.T) {
	r := mustRepo(t)
	now := time.Now().UTC()
	payload, checksum := snapshotArchive(t)
	artifacts := &fakeArtifacts{payload: payload, checksum: checksum, modified: now}

	service, _ := newService(t, r, newFakeStorage(), now)
	service.Artifacts = artifacts
	cfg := maintenance.OSVConfig{
		Repo: "osv-snapshots", Path: "osv/latest/osv-all.zip",
		LocalPath: filepath.Join(t.TempDir(), "osv-db"),
	}

	result, err := service.SyncOSVSnapshot(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("SyncOSVSnapshot: %v", err)
	}
	if !result.Updated || result.Records != 1 || result.IndexVersionID == nil {
		t.Fatalf("итог загрузки: %+v", result)
	}

	var active bool
	var records int
	if err := testPool.QueryRow(context.Background(),
		`SELECT is_active, record_count FROM vuln_index_version WHERE id=$1`,
		*result.IndexVersionID).Scan(&active, &records); err != nil {
		t.Fatalf("чтение версии снапшота: %v", err)
	}
	if !active || records != 1 {
		t.Errorf("строка версии: активна=%v, записей=%d", active, records)
	}

	// Активной может быть только одна версия.
	var others int
	if err := testPool.QueryRow(context.Background(),
		`SELECT count(*) FROM vuln_index_version WHERE is_active AND id <> $1`,
		*result.IndexVersionID).Scan(&others); err != nil {
		t.Fatalf("подсчёт активных версий: %v", err)
	}
	if others != 0 {
		t.Errorf("активных версий снапшота кроме новой: %d", others)
	}

	// Повторный вызов с тем же снапшотом ничего не меняет.
	again, err := service.SyncOSVSnapshot(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("повторная синхронизация: %v", err)
	}
	if again.Updated {
		t.Error("тот же снапшот посчитан новой версией")
	}
}

// Артефактори не настроено — это состояние, а не тишина: без снапшота каждый
// пакет уходит к DevSecOps вручную.
func TestSyncOSVSnapshotNeedsArtifactStore(t *testing.T) {
	r := mustRepo(t)
	service, _ := newService(t, r, newFakeStorage(), time.Now().UTC())
	if _, err := service.SyncOSVSnapshot(context.Background(), maintenance.OSVConfig{}, false); err == nil {
		t.Fatal("ожидалась ошибка про ненастроенное артефактори")
	}
}
