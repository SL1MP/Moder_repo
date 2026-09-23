package osv_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"moderation/internal/osv"
)

// oneRecord — снапшот из одной записи. Обёртка над snapshotZip из
// sync_test.go: тестам источников содержимое базы не важно, важно лишь то,
// что у разных снапшотов разные байты.
func oneRecord(t *testing.T, id string) []byte {
	t.Helper()
	return snapshotZip(t, map[string]string{
		"PyPI/" + id + ".json": `{"id":"` + id + `","affected":[{` +
			`"package":{"ecosystem":"PyPI","name":"vulnpkg"},` +
			`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.4.3"}]}]}]}`,
	})
}

func TestParseSourceKind(t *testing.T) {
	for value, want := range map[string]osv.SourceKind{
		"":            osv.SourceArtifactory,
		"artifactory": osv.SourceArtifactory,
		"HTTP":        osv.SourceHTTP,
		" file ":      osv.SourceFile,
	} {
		got, err := osv.ParseSourceKind(value)
		if err != nil {
			t.Errorf("%q: %v", value, err)
			continue
		}
		if got != want {
			t.Errorf("%q → %q, ожидалось %q", value, got, want)
		}
	}
	// Опечатка не должна молча превращаться в «читаем из артефактори»: там
	// файла может не быть вовсе, и сервис месяцами работал бы с пустой базой.
	if _, err := osv.ParseSourceKind("artifactor"); err == nil {
		t.Error("опечатка в OSV_DB_SOURCE принята как допустимое значение")
	}
}

// TestHTTPSourceUsesETagAsVersion — версия снапшота берётся из ETag: это
// ближайший аналог контрольной суммы, который отдаёт HTTP.
func TestHTTPSourceUsesETagAsVersion(t *testing.T) {
	payload := oneRecord(t, "GHSA-1111")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `W/"abcdef0123456789abcdef"`)
		w.Header().Set("Last-Modified", "Mon, 15 Jan 2024 10:00:00 GMT")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	src := osv.HTTPSource{URL: srv.URL + "/osv-all.zip"}
	remote, err := src.StatSnapshot(context.Background(), "", "")
	if err != nil {
		t.Fatalf("StatSnapshot: %v", err)
	}
	if remote == nil {
		t.Fatal("снапшот не найден, хотя сервер ответил 200")
	}
	// Кавычки и префикс слабого валидатора — часть синтаксиса заголовка, а не
	// значения: с ними одна и та же версия выглядела бы разной.
	if remote.Checksum != "abcdef0123456789abcdef" {
		t.Errorf("ETag разобран как %q", remote.Checksum)
	}
	if remote.LastModified.IsZero() {
		t.Error("Last-Modified не разобран")
	}
}

// TestHTTPSourceMissingFile — 404 означает «снапшота там нет», а не ошибку
// запроса: вызывающий код должен сказать администратору, что файл не выложили.
func TestHTTPSourceMissingFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	remote, err := osv.HTTPSource{URL: srv.URL + "/none.zip"}.
		StatSnapshot(context.Background(), "", "")
	if err != nil {
		t.Fatalf("404 отдан ошибкой: %v", err)
	}
	if remote != nil {
		t.Error("несуществующий файл выдан за существующий")
	}
}

// TestSyncIsIdempotentWithoutServerMetadata — сервер не отдаёт ни ETag, ни
// Last-Modified (так отвечает раздача без поддержки HEAD).
//
// Версия в этом случае берётся из содержимого файла. Без этого она
// вычислялась бы из текущего времени и менялась при каждой синхронизации:
// снапшот перекладывался бы заново каждые шесть часов, и каждый раз
// запускалась бы перепроверка всех одобренных пакетов — по базе, которая не
// менялась.
func TestSyncIsIdempotentWithoutServerMetadata(t *testing.T) {
	payload := oneRecord(t, "GHSA-2222")
	downloads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// Метаданных нет вовсе — ни ETag, ни Last-Modified.
			w.WriteHeader(http.StatusOK)
			return
		}
		downloads++
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	root := filepath.Join(t.TempDir(), "osv-db")
	index := osv.NewSnapshotIndex(root)
	src := osv.HTTPSource{URL: srv.URL + "/osv-all.zip"}

	first, err := index.Sync(context.Background(), src, "", "", false)
	if err != nil {
		t.Fatalf("первая синхронизация: %v", err)
	}
	if first == nil {
		t.Fatal("первая синхронизация ничего не загрузила")
	}
	// Версия — из содержимого файла, а не из текущего времени. Это и есть
	// суть: версия, вычисленная из времени, совпадает у двух синхронизаций
	// внутри одной секунды и расходится через минуту, то есть «не менялся»
	// превращается в «менялся» без единого изменения в базе.
	if want := osv.ChecksumOf(payload)[:16]; first.Version != want {
		t.Errorf("версия = %q, ожидалась %q — она должна выводиться из содержимого",
			first.Version, want)
	}

	second, err := index.Sync(context.Background(), src, "", "", false)
	if err != nil {
		t.Fatalf("вторая синхронизация: %v", err)
	}
	if second != nil {
		t.Errorf("снапшот перезагружен, хотя не менялся: версия %q → %q",
			first.Version, second.Version)
	}
	// Скачать файл во второй раз пришлось — иначе не узнать, изменился ли он;
	// но разложить и объявить новой версией — нет.
	if downloads != 2 {
		t.Errorf("скачиваний: %d, ожидалось 2", downloads)
	}
}

// TestFileSourceReadsFromDisk — снапшот, положенный на диск чужим процессом.
func TestFileSourceReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "osv-all.zip")
	payload := oneRecord(t, "GHSA-3333")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	src := osv.FileSource{Path: path}
	remote, err := src.StatSnapshot(context.Background(), "", "")
	if err != nil {
		t.Fatalf("StatSnapshot: %v", err)
	}
	if remote == nil || remote.SizeBytes != int64(len(payload)) {
		t.Fatalf("метаданные файла = %+v", remote)
	}
	body, err := src.ReadSnapshot(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Error("прочитано не то содержимое")
	}

	// Отсутствующий файл — «снапшота нет», а не ошибка чтения.
	missing, err := osv.FileSource{Path: filepath.Join(dir, "нет.zip")}.
		StatSnapshot(context.Background(), "", "")
	if err != nil {
		t.Errorf("отсутствующий файл отдан ошибкой: %v", err)
	}
	if missing != nil {
		t.Error("отсутствующий файл выдан за существующий")
	}

	// Каталог вместо файла — настоящая ошибка настройки, и молчать о ней
	// нельзя: распаковывать каталог как zip бессмысленно.
	if _, err := (osv.FileSource{Path: dir}).StatSnapshot(context.Background(), "", ""); err == nil {
		t.Error("каталог принят как файл снапшота")
	}
}

// TestFileSourceSyncNoticesReplacement — файл подменили, и снапшот
// перезагружается: контрольной суммы у файла на диске нет, поэтому изменение
// замечается по времени и размеру.
func TestFileSourceSyncNoticesReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "osv-all.zip")
	if err := os.WriteFile(path, oneRecord(t, "GHSA-4444"), 0o644); err != nil {
		t.Fatal(err)
	}

	index := osv.NewSnapshotIndex(filepath.Join(dir, "osv-db"))
	src := osv.FileSource{Path: path}

	first, err := index.Sync(context.Background(), src, "", "", false)
	if err != nil || first == nil {
		t.Fatalf("первая синхронизация: %v, %+v", err, first)
	}
	if again, err := index.Sync(context.Background(), src, "", "", false); err != nil || again != nil {
		t.Errorf("повторная синхронизация неизменного файла: %v, %+v", err, again)
	}

	// Тот же путь, другое содержимое и другое время изменения.
	if err := os.WriteFile(path, oneRecord(t, "GHSA-5555"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	second, err := index.Sync(context.Background(), src, "", "", false)
	if err != nil {
		t.Fatalf("синхронизация после подмены: %v", err)
	}
	if second == nil {
		t.Fatal("подменённый снапшот не загружен — сервис продолжил бы проверять по старой базе")
	}
	if second.Version == first.Version {
		t.Errorf("версия не изменилась: %q", second.Version)
	}
}
