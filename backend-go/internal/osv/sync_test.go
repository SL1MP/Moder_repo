package osv_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"moderation/internal/osv"
)

// Загрузка снапшота — единственное место, где база уязвимостей меняется
// целиком. Ошибка здесь не видна снаружи: конвейер продолжит отвечать, просто
// по старым или неполным данным.

// fakeSource — снапшот в памяти.
type fakeSource struct {
	payload  []byte
	checksum string
	modified time.Time
	missing  bool
	reads    int
}

type multiSource struct {
	items map[string]*fakeSource
}

type blockingSource struct {
	*fakeSource
	started chan struct{}
	release chan struct{}
}

func (s *blockingSource) ReadSnapshot(
	ctx context.Context, repo, path string,
) ([]byte, error) {
	close(s.started)
	select {
	case <-s.release:
		return s.fakeSource.ReadSnapshot(ctx, repo, path)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *multiSource) StatSnapshot(
	ctx context.Context, repo, path string,
) (*osv.RemoteSnapshot, error) {
	item := m.items[path]
	if item == nil {
		return nil, nil
	}
	return item.StatSnapshot(ctx, repo, path)
}

func (m *multiSource) ReadSnapshot(ctx context.Context, repo, path string) ([]byte, error) {
	item := m.items[path]
	if item == nil {
		return nil, fmt.Errorf("нет архива %s", path)
	}
	return item.ReadSnapshot(ctx, repo, path)
}

func (f *fakeSource) StatSnapshot(context.Context, string, string) (*osv.RemoteSnapshot, error) {
	if f.missing {
		return nil, nil
	}
	return &osv.RemoteSnapshot{
		Checksum: f.checksum, LastModified: f.modified, SizeBytes: int64(len(f.payload)),
	}, nil
}

func (f *fakeSource) ReadSnapshot(context.Context, string, string) ([]byte, error) {
	f.reads++
	return f.payload, nil
}

// snapshotZip — архив со снапшотом: записи разложены по экосистемам.
func snapshotZip(t *testing.T, records map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range records {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("сборка архива: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("запись в архив: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("закрытие архива: %v", err)
	}
	return buf.Bytes()
}

func advisory(id, ecosystem, pkg, introduced, fixed string) string {
	doc := map[string]any{
		"id": id, "summary": "тестовая запись", "severity": []any{},
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": ecosystem, "name": pkg},
			"ranges": []any{map[string]any{
				"type": "ECOSYSTEM",
				"events": []any{
					map[string]any{"introduced": introduced},
					map[string]any{"fixed": fixed},
				},
			}},
		}},
	}
	data, _ := json.Marshal(doc)
	return string(data)
}

func newSource(t *testing.T, records map[string]string) *fakeSource {
	t.Helper()
	payload := snapshotZip(t, records)
	digest := sha256.Sum256(payload)
	return &fakeSource{
		payload: payload, checksum: hex.EncodeToString(digest[:]),
		modified: time.Date(2026, 9, 20, 4, 0, 0, 0, time.UTC),
	}
}

func TestSyncDownloadsAndUnpacks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	source := newSource(t, map[string]string{
		"PyPI/GHSA-1.json": advisory("GHSA-1", "PyPI", "requests", "0", "2.32.0"),
		"PyPI/GHSA-2.json": advisory("GHSA-2", "PyPI", "urllib3", "0", "2.0.0"),
		"README.txt":       "не запись, игнорируется",
	})

	info, err := index.Sync(context.Background(), source, "osv-snapshots", "osv/latest/osv-all.zip", false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if info == nil {
		t.Fatal("снапшота не было — загрузка обязана была состояться")
	}
	if info.RecordCount != 2 {
		t.Errorf("записей = %d, ожидалось 2 (не-json не считается)", info.RecordCount)
	}
	if _, err := os.Stat(filepath.Join(root, "snapshot.json")); err != nil {
		t.Errorf("метаданные снапшота не записаны: %v", err)
	}

	// Индекс сразу отвечает по новым данным.
	findings, err := index.Query(context.Background(), "pypi", "requests", "2.31.0")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(findings) != 1 || findings[0].ExternalID != "GHSA-1" {
		t.Fatalf("находки по свежему снапшоту: %+v", findings)
	}
}

func TestSyncRejectsConcurrentProcessForSameRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	source := &blockingSource{
		fakeSource: newSource(t, map[string]string{
			"PyPI/GHSA-1.json": advisory("GHSA-1", "PyPI", "requests", "0", "2.32.0"),
		}),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		_, err := index.Sync(context.Background(), source, "r", "p", false)
		done <- err
	}()
	<-source.started

	_, err := osv.NewSnapshotIndex(root).Sync(
		context.Background(), source.fakeSource, "r", "p", false,
	)
	if !errors.Is(err, osv.ErrSnapshotSyncInProgress) {
		t.Errorf("параллельная синхронизация: error=%v, ожидался ErrSnapshotSyncInProgress", err)
	}
	close(source.release)
	if err := <-done; err != nil {
		t.Fatalf("первая синхронизация: %v", err)
	}
}

func TestSyncManyCombinesPyPIAndNpmAtomically(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	source := &multiSource{items: map[string]*fakeSource{
		"osv/latest/osv-pypi.zip": newSource(t, map[string]string{
			"GHSA-PYPI.json": advisory("GHSA-PYPI", "PyPI", "requests", "0", "2.32.0"),
		}),
		"osv/latest/osv-npm.zip": newSource(t, map[string]string{
			"GHSA-NPM.json": advisory("GHSA-NPM", "npm", "lodash", "0", "4.17.22"),
		}),
	}}
	specs := []osv.SnapshotSpec{
		{Ecosystem: "PyPI", Path: "osv/latest/osv-pypi.zip"},
		{Ecosystem: "npm", Path: "osv/latest/osv-npm.zip"},
	}

	info, err := index.SyncMany(context.Background(), source, "osv-snapshots", specs, false)
	if err != nil {
		t.Fatalf("SyncMany: %v", err)
	}
	if info == nil || info.RecordCount != 2 {
		t.Fatalf("составной индекс: %+v", info)
	}
	for _, tc := range []struct {
		manager, name, version, advisory string
	}{
		{"pypi", "requests", "2.31.0", "GHSA-PYPI"},
		{"npm", "lodash", "4.17.21", "GHSA-NPM"},
	} {
		findings, err := index.Query(context.Background(), tc.manager, tc.name, tc.version)
		if err != nil || len(findings) != 1 || findings[0].ExternalID != tc.advisory {
			t.Errorf("%s: находки=%+v, ошибка=%v", tc.manager, findings, err)
		}
	}

	again, err := index.SyncMany(context.Background(), source, "osv-snapshots", specs, false)
	if err != nil || again != nil {
		t.Fatalf("повторная синхронизация: info=%+v, error=%v", again, err)
	}
	if source.items[specs[0].Path].reads != 1 || source.items[specs[1].Path].reads != 1 {
		t.Errorf("неизменившиеся архивы скачаны повторно")
	}
}

func TestSyncManyKeepsPreviousIndexWhenOneArchiveMissing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	full := &multiSource{items: map[string]*fakeSource{
		"pypi.zip": newSource(t, map[string]string{
			"one.json": advisory("PYPI-1", "PyPI", "requests", "0", "2.32.0"),
		}),
		"npm.zip": newSource(t, map[string]string{
			"two.json": advisory("NPM-1", "npm", "lodash", "0", "4.17.22"),
		}),
	}}
	specs := []osv.SnapshotSpec{{Ecosystem: "PyPI", Path: "pypi.zip"}, {Ecosystem: "npm", Path: "npm.zip"}}
	if _, err := index.SyncMany(context.Background(), full, "r", specs, false); err != nil {
		t.Fatalf("первая синхронизация: %v", err)
	}

	missing := &multiSource{items: map[string]*fakeSource{"pypi.zip": full.items["pypi.zip"]}}
	if _, err := index.SyncMany(context.Background(), missing, "r", specs, true); err == nil {
		t.Fatal("отсутствующий npm-архив должен быть ошибкой")
	}
	findings, err := index.Query(context.Background(), "npm", "lodash", "4.17.21")
	if err != nil || len(findings) != 1 {
		t.Fatalf("прежний составной индекс потерян: findings=%+v, error=%v", findings, err)
	}
}

// Повторный вызов с тем же снапшотом не должен ни качать, ни раскладывать
// заново: иначе каждая синхронизация выглядела бы как новая версия базы и
// запускала перепроверку всех одобренных пакетов.
func TestSyncIsIdempotent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	source := newSource(t, map[string]string{
		"PyPI/GHSA-1.json": advisory("GHSA-1", "PyPI", "requests", "0", "2.32.0"),
	})
	ctx := context.Background()

	if _, err := index.Sync(ctx, source, "r", "p", false); err != nil {
		t.Fatalf("первая загрузка: %v", err)
	}
	info, err := index.Sync(ctx, source, "r", "p", false)
	if err != nil {
		t.Fatalf("вторая загрузка: %v", err)
	}
	if info != nil {
		t.Fatal("тот же снапшот не должен считаться новой версией")
	}
	if source.reads != 1 {
		t.Errorf("скачиваний: %d, ожидалось 1", source.reads)
	}

	// --force перезагружает тот же самый.
	if _, err := index.Sync(ctx, source, "r", "p", true); err != nil {
		t.Fatalf("принудительная загрузка: %v", err)
	}
	if source.reads != 2 {
		t.Errorf("скачиваний после --force: %d, ожидалось 2", source.reads)
	}
}

// Битые байты не должны заменить рабочую базу.
func TestSyncRejectsChecksumMismatch(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	source := newSource(t, map[string]string{
		"PyPI/GHSA-1.json": advisory("GHSA-1", "PyPI", "requests", "0", "2.32.0"),
	})
	source.checksum = "0000000000000000000000000000000000000000000000000000000000000000"

	_, err := index.Sync(context.Background(), source, "r", "p", false)
	if err == nil {
		t.Fatal("несовпадение контрольной суммы обязано быть ошибкой")
	}
	if _, statErr := os.Stat(filepath.Join(root, "snapshot.json")); statErr == nil {
		t.Error("каталог снапшота заполнен несмотря на битые байты")
	}
}

// Пустой архив — это не «уязвимостей нет», а сломанная выгрузка.
func TestSyncRejectsEmptySnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	source := newSource(t, map[string]string{"README.txt": "ни одной записи"})

	if _, err := index.Sync(context.Background(), source, "r", "p", false); err == nil {
		t.Fatal("снапшот без записей обязан быть ошибкой")
	}
}

// Пока новый снапшот не разложен, прежний обязан остаться на месте: конвейер
// работает параллельно, и «база не загружена» отправило бы пакеты к DevSecOps.
func TestSyncKeepsPreviousSnapshotOnFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	ctx := context.Background()

	good := newSource(t, map[string]string{
		"PyPI/GHSA-1.json": advisory("GHSA-1", "PyPI", "requests", "0", "2.32.0"),
	})
	if _, err := index.Sync(ctx, good, "r", "p", false); err != nil {
		t.Fatalf("первая загрузка: %v", err)
	}

	broken := newSource(t, map[string]string{"README.txt": "мусор"})
	broken.modified = good.modified.Add(time.Hour)
	if _, err := index.Sync(ctx, broken, "r", "p", false); err == nil {
		t.Fatal("сломанный снапшот обязан быть ошибкой")
	}

	findings, err := index.Query(ctx, "pypi", "requests", "2.31.0")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("прежний снапшот потерян: находок %d", len(findings))
	}
}

// Новый снапшот обязан начать отвечать сразу. Индекс держит разобранные
// записи в памяти, и без сброса кэша конвейер продолжил бы выносить вердикт по
// прежней базе, хотя на диске уже новая.
func TestSyncInvalidatesCache(t *testing.T) {
	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	ctx := context.Background()

	old := newSource(t, map[string]string{
		"PyPI/GHSA-1.json": advisory("GHSA-1", "PyPI", "requests", "0", "2.32.0"),
	})
	if _, err := index.Sync(ctx, old, "r", "p", false); err != nil {
		t.Fatalf("первая загрузка: %v", err)
	}
	// Запрос до обновления — кэш заполняется прежними данными.
	if findings, err := index.Query(ctx, "pypi", "requests", "2.31.0"); err != nil || len(findings) != 1 {
		t.Fatalf("находки по первому снапшоту: %+v (%v)", findings, err)
	}

	fresh := newSource(t, map[string]string{
		"PyPI/GHSA-1.json": advisory("GHSA-1", "PyPI", "requests", "0", "2.32.0"),
		"PyPI/GHSA-9.json": advisory("GHSA-9", "PyPI", "requests", "0", "2.33.0"),
	})
	fresh.modified = old.modified.Add(time.Hour)
	if _, err := index.Sync(ctx, fresh, "r", "p", false); err != nil {
		t.Fatalf("вторая загрузка: %v", err)
	}

	findings, err := index.Query(ctx, "pypi", "requests", "2.31.0")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("после обновления найдено %d записей, ожидалось 2 — отвечает прежний кэш", len(findings))
	}
}

// «Снапшот не выложили» — состояние, о котором надо сказать прямо, а не
// молчаливый ноль находок.
func TestSyncNamesMissingSnapshot(t *testing.T) {
	index := osv.NewSnapshotIndex(filepath.Join(t.TempDir(), "osv-db"))
	source := &fakeSource{missing: true}

	_, err := index.Sync(context.Background(), source, "osv-snapshots", "osv/latest/osv-all.zip", false)
	if err == nil {
		t.Fatal("отсутствие снапшота обязано быть ошибкой")
	}
	if got := fmt.Sprint(err); !bytes.Contains([]byte(got), []byte("osv-snapshots")) {
		t.Errorf("в сообщении нет адреса снапшота: %s", got)
	}
}
