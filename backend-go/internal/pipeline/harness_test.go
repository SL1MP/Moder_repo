package pipeline_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/artifactstore"
	"moderation/internal/db"
	"moderation/internal/domain"
	"moderation/internal/osv"
	"moderation/internal/pipeline"
	"moderation/internal/policy"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/sandbox"
	"moderation/internal/scanners"
	"moderation/internal/storage"
)

// Тесты конвейера идут на РЕАЛЬНОМ Postgres (принцип sentrix, docs/testing.md):
// конвейер — это в основном переходы статусов и строки pipeline_step, и мок
// репозитория проверял бы соответствие заглушке, а не поведение.
//
// Внешние же зависимости (реестр, хранилище, артефактори, сканеры) —
// подставные, но не «моки, возвращающие что сказано»: каждая реализует свой
// контракт целиком, включая ошибки.

// testPool — пул для служебных запросов теста (очистка фикстур). Хранится
// рядом с Repo: чистка — это не операция сервиса, и держать её в репозитории
// значило бы возить по бою метод, стирающий историю проверок.
var testPool *pgxpool.Pool

func mustRepo(t *testing.T) (*repo.Repo, func()) {
	t.Helper()
	dsn := os.Getenv("MODERATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MODERATION_TEST_POSTGRES_DSN не задан — пропускаю интеграционный тест (см. docs/testing.md)")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("подключение к тестовому Postgres: %v", err)
	}
	testPool = pool
	return repo.New(pool), func() { pool.Close() }
}

// resetVersion возвращает версию пакета в исходное состояние.
//
// База между прогонами `go test` не пересоздаётся, а db_check (шаг 0)
// терминален для уже одобренной версии: без сброса тест, однажды доведший
// пакет до approved, во второй раз останавливался бы на первом шаге и
// «проходил», ничего не проверив. Именно это и произошло — девять тестов
// молча зеленели на approved.
func resetVersion(t *testing.T, packageVersionID int64) {
	t.Helper()
	ctx := context.Background()
	statements := []string{
		// request_item удаляется каскадом вместе с pipeline_step и scan_report.
		`DELETE FROM request_item WHERE package_version_id = $1`,
		`DELETE FROM artifact WHERE package_version_id = $1`,
		`DELETE FROM code_finding WHERE package_version_id = $1`,
		`DELETE FROM vulnerability WHERE package_version_id = $1`,
		`UPDATE package_version SET status = 'new', status_reason = NULL,
		     security_override_at = NULL, security_override_by_id = NULL,
		     security_override_comment = NULL, approved_at = NULL, revoked_at = NULL,
		     quarantine_until = NULL, max_vuln_score = NULL, vuln_index_version_id = NULL,
		     license_spdx = NULL, license_source = NULL
		 WHERE id = $1`,
	}
	for _, stmt := range statements {
		if _, err := testPool.Exec(ctx, stmt, packageVersionID); err != nil {
			t.Fatalf("сброс фикстуры версии: %v", err)
		}
	}
}

// --------------------------------------------------------------------- подставные зависимости

// fakeFetcher — скачивание артефакта. Отдаёт заранее подготовленные байты по
// адресу; неизвестный адрес — ошибка, как у настоящего реестра.
type fakeFetcher struct {
	files map[string][]byte
	calls int
	mu    sync.Mutex
}

func (f *fakeFetcher) Fetch(_ context.Context, url string, limit int64) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	data, ok := f.files[url]
	if !ok {
		return nil, fmt.Errorf("реестр ответил 404 (%s)", url)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("размер артефакта %d байт превышает лимит %d", len(data), limit)
	}
	return data, nil
}

// fakeRegistryHTTP — фейковый HTTP-клиент реестра метаданных.
//
// fallback отвечает на любой адрес: имена пакетов в тестах namespace'ятся
// именем теста, и держать карту точных адресов пришлось бы пересобирать в
// каждом тесте. Проверка того, что адрес собран верно, — задача тестов пакета
// registry, а не конвейера.
type fakeRegistryHTTP struct {
	responses map[string]string
	fallback  string
	err       error
}

func (f *fakeRegistryHTTP) Do(req *http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	body, ok := f.responses[req.URL.String()]
	status := 200
	if !ok {
		if f.fallback != "" {
			body = f.fallback
		} else {
			status, body = 404, `{"message":"not found"}`
		}
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}, nil
}

// fakeArtifactStore — артефактори в памяти.
type fakeArtifactStore struct {
	published  map[string][]byte
	dryRun     bool
	publishErr error
	baseURL    string
}

func newFakeArtifactStore() *fakeArtifactStore {
	return &fakeArtifactStore{published: map[string][]byte{}, baseURL: "https://art.test"}
}

func (f *fakeArtifactStore) Kind() string { return artifactstore.KindGeneric }

func (f *fakeArtifactStore) ArtifactURL(t artifactstore.Target) string {
	return fmt.Sprintf("%s/%s/%s", f.baseURL, t.Repo, t.Path)
}

func (f *fakeArtifactStore) Exists(_ context.Context, t artifactstore.Target) (bool, error) {
	_, ok := f.published[t.Repo+"/"+t.Path]
	return ok, nil
}

func (f *fakeArtifactStore) Publish(_ context.Context, t artifactstore.Target, data []byte) (string, error) {
	if f.publishErr != nil {
		return "", f.publishErr
	}
	f.published[t.Repo+"/"+t.Path] = data
	return f.ArtifactURL(t), nil
}

func (f *fakeArtifactStore) Delete(_ context.Context, t artifactstore.Target) (bool, error) {
	key := t.Repo + "/" + t.Path
	if _, ok := f.published[key]; !ok {
		return false, nil
	}
	delete(f.published, key)
	return true, nil
}

func (f *fakeArtifactStore) StatFile(_ context.Context, repoName, path string) (*artifactstore.RemoteFile, error) {
	data, ok := f.published[repoName+"/"+path]
	if !ok {
		return nil, nil
	}
	return &artifactstore.RemoteFile{Path: path, SizeBytes: int64(len(data))}, nil
}

func (f *fakeArtifactStore) ReadFile(_ context.Context, repoName, path string) ([]byte, error) {
	data, ok := f.published[repoName+"/"+path]
	if !ok {
		return nil, fmt.Errorf("нет такого файла")
	}
	return data, nil
}

func (f *fakeArtifactStore) WriteFile(_ context.Context, repoName, path string, data []byte, _ string) error {
	f.published[repoName+"/"+path] = data
	return nil
}

func (f *fakeArtifactStore) DeleteFile(_ context.Context, repoName, path string) (bool, error) {
	key := repoName + "/" + path
	if _, ok := f.published[key]; !ok {
		return false, nil
	}
	delete(f.published, key)
	return true, nil
}

func (f *fakeArtifactStore) ListFiles(_ context.Context, repoName, prefix string) ([]artifactstore.RemoteFile, error) {
	var out []artifactstore.RemoteFile
	for key, data := range f.published {
		path, ok := strings.CutPrefix(key, repoName+"/")
		if !ok || !strings.HasPrefix(path, prefix) {
			continue
		}
		out = append(out, artifactstore.RemoteFile{Path: path, SizeBytes: int64(len(data))})
	}
	return out, nil
}

// MoveFile — перенос поддержан: тесты обязаны проходить основной путь
// публикации (перенос внутри артефактори), а не только запасной.
func (f *fakeArtifactStore) MoveFile(_ context.Context, srcRepo, srcPath, dstRepo, dstPath string) error {
	// publishErr относится и к переносу: для вызывающего это одно и то же —
	// «артефактори не принял пакет». Проверять отказ только на запасном пути
	// значило бы не проверять основной.
	if f.publishErr != nil {
		return f.publishErr
	}
	src := srcRepo + "/" + srcPath
	data, ok := f.published[src]
	if !ok {
		return fmt.Errorf("переносить нечего: в %s нет файла %s", srcRepo, srcPath)
	}
	delete(f.published, src)
	f.published[dstRepo+"/"+dstPath] = data
	return nil
}

func (f *fakeArtifactStore) DryRun() bool { return f.dryRun }

// fakeSandbox — песочница с заранее заданным вердиктом.
//
// Настоящая реализация контракта, а не заглушка на один вызов: считает
// обращения и умеет быть ненастроенной (available=false) — именно это
// различие шаг обязан отличать от «чисто».
type fakeSandbox struct {
	available bool
	result    sandbox.Result
	err       error
	calls     int
	// lastFile — имя файла, которое шаг отправил. Проверяется тестом: в
	// песочницу обязан уходить тот файл, который будет опубликован.
	lastFile string
	lastSize int
}

func newFakeSandbox() *fakeSandbox {
	return &fakeSandbox{
		available: true,
		result:    sandbox.Result{Verdict: sandbox.VerdictClean, ScanID: "scan-1"},
	}
}

func (f *fakeSandbox) Available() bool { return f.available }

func (f *fakeSandbox) Endpoint() string { return "https://sandbox.test" }

func (f *fakeSandbox) Check(_ context.Context, filename string, payload []byte) (sandbox.Result, error) {
	f.calls++
	f.lastFile, f.lastSize = filename, len(payload)
	if f.err != nil {
		return sandbox.Result{}, f.err
	}
	result := f.result
	if result.ScanID != "" && result.TaskURL == "" {
		result.TaskURL = f.Endpoint() + "/tasks/" + result.ScanID
	}
	return result, nil
}

// fakeScanner — сканер содержимого с заранее заданным исходом.
type fakeScanner struct {
	name    string
	outcome scanners.Outcome
	err     error
	calls   int
}

func (f *fakeScanner) Name() string { return f.name }

func (f *fakeScanner) Scan(context.Context, string) (scanners.Outcome, error) {
	f.calls++
	return f.outcome, f.err
}

// --------------------------------------------------------------------- сборка окружения

type env struct {
	t       *testing.T
	repo    *repo.Repo
	storage *storage.Memory
	// reports — хранилище отчётов, отдельное от промежуточной зоны: в бою это
	// разные репозитории артефактори, и тест, складывающий их в одно место,
	// не заметил бы, что отчёт вычищается вместе с артефактом.
	reports   *storage.Memory
	sandbox   *fakeSandbox
	artifacts *fakeArtifactStore
	fetcher   *fakeFetcher
	banner    *fakeScanner
	sast      *fakeScanner
	index     *osv.StaticIndex
	registry  *registry.Registry
	config    pipeline.Config
	now       time.Time
}

// tarGz собирает артефакт-архив: сканерам и распаковщику нужен настоящий файл.
func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	w := tar.NewWriter(gz)
	for name, body := range files {
		if err := w.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const artifactURL = "https://files.test/pkg-1.0.0.tar.gz"

func newEnv(t *testing.T, r *repo.Repo) *env {
	t.Helper()
	payload := tarGz(t, map[string]string{"pkg/main.py": "print('ok')\n"})

	// Метаданные: дата публикации заведомо старая, чтобы карантин не мешал
	// тестам про более поздние шаги; тест карантина задаёт свои.
	published := time.Now().UTC().AddDate(0, 0, -400).Format(time.RFC3339)
	reg := registry.New(registry.Config{
		PyPIURL: "https://pypi.test",
		HTTP: &fakeRegistryHTTP{fallback: `{
		  "info": {"license": "MIT", "classifiers": []},
		  "urls": [{"packagetype": "sdist", "url": "` + artifactURL + `",
		            "filename": "pkg-1.0.0.tar.gz", "size": 100,
		            "upload_time_iso_8601": "` + published + `", "digests": {}}]
		}`},
	})

	staging := storage.NewMemory("test-staging")
	artifacts := newFakeArtifactStore()
	// Перенос внутри артефактори — основной путь публикации, и проверяться он
	// обязан так же, как запасной. Приёмник кладёт байты в тот же фейковый
	// артефактори, куда их положила бы выгрузка.
	staging.SetMoveSink(func(ctx context.Context, _ string, data []byte, dstRepo, dstPath string) error {
		// publishErr относится и к переносу: для вызывающего это одно и то же —
		// «артефактори не принял пакет». Проверять отказ только на запасном
		// пути (скачать и выгрузить) значило бы не проверять основной.
		if artifacts.publishErr != nil {
			return artifacts.publishErr
		}
		return artifacts.WriteFile(ctx, dstRepo, dstPath, data, "application/octet-stream")
	})

	return &env{
		t: t, repo: r,
		storage:   staging,
		reports:   storage.NewMemory("test-reports"),
		sandbox:   newFakeSandbox(),
		artifacts: artifacts,
		fetcher:   &fakeFetcher{files: map[string][]byte{artifactURL: payload}},
		banner:    &fakeScanner{name: "yara", outcome: scanners.Outcome{Available: true, Detail: "правил сработало: 0"}},
		sast:      &fakeScanner{name: "semgrep", outcome: scanners.Outcome{Available: true, Detail: "файлов: 1"}},
		index:     &osv.StaticIndex{Version: &osv.IndexVersion{Version: "test-1", Source: "static", PublishedAt: ptrTime(time.Now().UTC())}},
		registry:  reg,
		now:       time.Now().UTC(),
		config: pipeline.Config{
			QuarantineDays:       14,
			MaxArtifactSizeBytes: 10 << 20,
			VulnMaxScore:         70,
			OSVMaxStalenessDays:  7,
			SandboxEnabled:       true,
			BannerScanEnabled:    true,
			SASTEnabled:          true,
			SASTMinSeverity:      "medium",
			ArtifactBaseURL:      "https://art.test",
			ArtifactRepos:        map[string]string{"pypi": "pypi-internal"},
		},
	}
}

func (e *env) deps() pipeline.Deps {
	return pipeline.Deps{
		Repo: e.repo, Storage: e.storage, Reports: e.reports, Artifacts: e.artifacts,
		Index: e.index, Registry: e.registry, Sandbox: e.sandbox,
		Banner: e.banner, SAST: e.sast, Fetch: e.fetcher,
		Now: func() time.Time { return e.now },
	}
}

// allowedLicenses — справочник, разрешающий MIT. Настоящий тип политики, а не
// заглушка: тесты конвейера должны ходить через ту же проверку, что и бой.
func allowedLicenses() pipeline.LicensePolicy {
	return licensePolicy("MIT")
}

func licensePolicy(allowed ...string) *policy.LicensePolicy {
	p := &policy.LicensePolicy{
		Allowed:   map[string]policy.LicenseEntry{},
		Forbidden: map[string]policy.LicenseEntry{},
	}
	for _, spdx := range allowed {
		p.Allowed[strings.ToLower(spdx)] = policy.LicenseEntry{SPDXID: spdx, Allowed: true}
	}
	return p
}

func (e *env) context(pkg *domain.Package, ver *domain.PackageVersion, item *domain.RequestItem) *pipeline.Context {
	return &pipeline.Context{
		Package: pkg, Version: ver, Item: item,
		Config: e.config, Deps: e.deps(), Lic: allowedLicenses(),
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// setup создаёт пакет, версию, заявку и пакет заявки, готовые к прогону.
//
// Имя пакета namespace'ится именем теста. База между тестами общая, а db_check
// (шаг 0) терминален для уже одобренной версии: без изоляции тест, идущий
// после успешного золотого пути, получал бы «версия уже одобрена» и
// останавливался на первом же шаге. Ровно это и произошло при первом прогоне —
// девять тестов «прошли» с approved, ничего не проверив.
func setup(t *testing.T, r *repo.Repo, name, version string) (*domain.Package, *domain.PackageVersion, *domain.RequestItem) {
	t.Helper()
	ctx := context.Background()
	name = name + "-" + testSlug(t)

	user, err := r.GetOrCreateUser(ctx, "tester", "Тестовый пользователь")
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	pkg, err := r.GetOrCreatePackage(ctx, "pypi", name, name)
	if err != nil {
		t.Fatalf("GetOrCreatePackage: %v", err)
	}
	ver, err := r.CreatePackageVersion(ctx, pkg.ID, version, version)
	if err != nil {
		t.Fatalf("CreatePackageVersion: %v", err)
	}
	resetVersion(t, ver.ID)
	ver, err = r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatalf("GetPackageVersion после сброса: %v", err)
	}

	req, err := r.CreateModerationRequest(ctx, domain.ModerationRequest{
		AuthorID: user.ID, Manager: "pypi", Status: "pending", Source: "api",
	})
	if err != nil {
		t.Fatalf("CreateModerationRequest: %v", err)
	}
	item, err := r.CreateRequestItem(ctx, domain.RequestItem{
		RequestID: req.ID, PackageVersionID: ver.ID,
		RequestedName: name, RequestedVersion: version,
		DependencyKind: "direct", Status: "queued",
	})
	if err != nil {
		t.Fatalf("CreateRequestItem: %v", err)
	}
	return pkg, ver, item
}

// stepsByCode — результаты шагов прогона, по коду.
func stepsByCode(t *testing.T, r *repo.Repo, itemID int64) map[string]domain.PipelineStep {
	t.Helper()
	steps, err := r.ListStepsByItem(context.Background(), itemID)
	if err != nil {
		t.Fatalf("ListStepsByItem: %v", err)
	}
	out := make(map[string]domain.PipelineStep, len(steps))
	for _, s := range steps {
		out[s.StepCode] = s
	}
	return out
}

// registryWithChecksum — реестр, заявляющий заданную контрольную сумму
// артефакта. Нужен тестам шага скачивания: сумма сверяется ДО записи в
// хранилище, и подменить её иначе негде.
func registryWithChecksum(t *testing.T, algo, checksum string) *registry.Registry {
	t.Helper()
	published := time.Now().UTC().AddDate(0, 0, -400).Format(time.RFC3339)
	digests := ""
	if algo == "sha256" {
		digests = `"digests": {"sha256": "` + checksum + `"}`
	} else {
		// Алгоритмы, которые pypi не отдаёт (go h1), подставляем через то же
		// поле: плагину важен факт заявленной суммы, а не её происхождение.
		digests = `"digests": {}`
	}
	body := `{
	  "info": {"license": "MIT", "classifiers": []},
	  "urls": [{"packagetype": "sdist", "url": "` + artifactURL + `",
	            "filename": "pkg-1.0.0.tar.gz", "size": 100,
	            "upload_time_iso_8601": "` + published + `", ` + digests + `}]
	}`
	reg := registry.New(registry.Config{
		PyPIURL: "https://pypi.test",
		HTTP:    &fakeRegistryHTTP{fallback: body},
	})
	if algo == "sha256" {
		return reg
	}
	// Для неподдержанного алгоритма подменяем плагин обёрткой: сумму с
	// алгоритмом h1 через ответ pypi не выразить.
	return registry.NewWithPlugin(reg, &checksumOverridePlugin{
		Plugin: mustPlugin(t, reg, "pypi"), algo: algo, checksum: checksum,
	})
}

func mustPlugin(t *testing.T, reg *registry.Registry, manager string) registry.Plugin {
	t.Helper()
	p, err := reg.Get(manager)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// checksumOverridePlugin подменяет заявленную сумму в метаданных.
type checksumOverridePlugin struct {
	registry.Plugin
	algo, checksum string
}

func (p *checksumOverridePlugin) FetchMetadata(ctx context.Context, ref registry.Ref) (registry.Metadata, error) {
	meta, err := p.Plugin.FetchMetadata(ctx, ref)
	if err != nil {
		return meta, err
	}
	meta.ChecksumAlgo, meta.Checksum = p.algo, p.checksum
	return meta, nil
}

// testSlug — имя теста, пригодное для имени пакета: подтесты дают «/» и
// пробелы, которые в имени пакета быть не должны.
func testSlug(t *testing.T) string {
	var b strings.Builder
	for _, c := range strings.ToLower(t.Name()) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteRune(c)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
