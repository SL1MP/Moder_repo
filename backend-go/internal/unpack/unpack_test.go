package unpack_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"moderation/internal/unpack"
)

// zipBytes собирает zip в памяти. entries — имя -> содержимое.
func zipBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip.Create(%q): %v", name, err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatalf("запись в zip: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("закрытие zip: %v", err)
	}
	return buf.Bytes()
}

// tarGzBytes собирает tar.gz в памяти; links — символические ссылки имя -> цель.
func tarGzBytes(t *testing.T, files map[string]string, links map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	w := tar.NewWriter(gz)
	for name, body := range files {
		if err := w.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %q: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("tar write %q: %v", name, err)
		}
	}
	for name, target := range links {
		if err := w.WriteHeader(&tar.Header{
			Name: name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: target,
		}); err != nil {
			t.Fatalf("tar symlink %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("закрытие tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("закрытие gzip: %v", err)
	}
	return buf.Bytes()
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение %s: %v", path, err)
	}
	return string(data)
}

func TestZipUnpacked(t *testing.T) {
	payload := zipBytes(t, map[string]string{
		"pkg/__init__.py": "print('hi')\n",
		"pkg/core.py":     "x = 1\n",
	})
	res, err := unpack.Artifact(payload, "pkg-1.0.whl", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.Files != 2 {
		t.Errorf("Files = %d, ожидалось 2", res.Files)
	}
	if got := read(t, filepath.Join(res.Root, "pkg", "core.py")); got != "x = 1\n" {
		t.Errorf("содержимое core.py = %q", got)
	}
}

func TestTarGzUnpacked(t *testing.T) {
	payload := tarGzBytes(t, map[string]string{"six-1.16.0/six.py": "__version__ = '1.16.0'\n"}, nil)
	res, err := unpack.Artifact(payload, "six-1.16.0.tar.gz", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.Files != 1 {
		t.Errorf("Files = %d, ожидалось 1", res.Files)
	}
	if !strings.Contains(read(t, filepath.Join(res.Root, "six-1.16.0", "six.py")), "1.16.0") {
		t.Error("содержимое six.py не распаковано")
	}
}

// TestZipSlipRejected — путь, выводящий за пределы каталога, не должен создать
// файл снаружи. Это главная причина существования пакета: архив приходит из
// внешнего мира.
func TestZipSlipRejected(t *testing.T) {
	payload := zipBytes(t, map[string]string{
		"../../evil.py": "import os\n",
		"ok.py":         "fine\n",
	})
	res, err := unpack.Artifact(payload, "evil.whl", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.SkippedUnsafe != 1 {
		t.Errorf("SkippedUnsafe = %d, ожидался 1 отклонённый путь", res.SkippedUnsafe)
	}
	if res.Files != 1 {
		t.Errorf("Files = %d, ожидался только ok.py", res.Files)
	}
	// Ничего не должно появиться выше каталога содержимого.
	outside := filepath.Join(filepath.Dir(filepath.Dir(res.Root)), "evil.py")
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Errorf("файл создан за пределами каталога распаковки: %s", outside)
	}
}

func TestAbsolutePathRejected(t *testing.T) {
	payload := tarGzBytes(t, map[string]string{"/etc/passwd": "root:x:0:0\n"}, nil)
	res, err := unpack.Artifact(payload, "evil.tar.gz", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.Files != 0 {
		t.Errorf("Files = %d, абсолютный путь должен быть отклонён", res.Files)
	}
	if res.SkippedUnsafe != 1 {
		t.Errorf("SkippedUnsafe = %d, ожидался 1", res.SkippedUnsafe)
	}
}

// TestSymlinkSkipped — ссылки не распаковываются вовсе (см. package doc).
func TestSymlinkSkipped(t *testing.T) {
	payload := tarGzBytes(t,
		map[string]string{"pkg/real.py": "ok\n"},
		map[string]string{"pkg/link.py": "/etc/passwd"},
	)
	res, err := unpack.Artifact(payload, "pkg.tar.gz", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.SkippedUnsafe != 1 {
		t.Errorf("SkippedUnsafe = %d, ссылка должна быть пропущена", res.SkippedUnsafe)
	}
	if _, err := os.Lstat(filepath.Join(res.Root, "pkg", "link.py")); !os.IsNotExist(err) {
		t.Error("символическая ссылка всё-таки создана")
	}
}

// TestFileCountLimit — архивная бомба по числу файлов: распаковка обрывается,
// Truncated выставлен, и это попадает в Notes (шаг покажет это DevSecOps).
func TestFileCountLimit(t *testing.T) {
	entries := make(map[string]string, 50)
	for i := 0; i < 50; i++ {
		entries[filepath.Join("many", string(rune('a'+i%26))+string(rune('a'+i/26))+".txt")] = "x"
	}
	res, err := unpack.Artifact(zipBytes(t, entries), "bomb.zip", unpack.Limits{MaxFiles: 10})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.Files != 10 {
		t.Errorf("Files = %d, ожидалось ровно 10 (лимит)", res.Files)
	}
	if !res.Truncated {
		t.Error("Truncated не выставлен при упоре в лимит файлов")
	}
	if len(res.Notes) == 0 {
		t.Error("ограничение распаковки не отражено в Notes")
	}
}

func TestTotalBytesLimit(t *testing.T) {
	big := strings.Repeat("A", 4096)
	res, err := unpack.Artifact(
		zipBytes(t, map[string]string{"a.txt": big, "b.txt": big, "c.txt": big}),
		"big.zip",
		unpack.Limits{MaxTotalBytes: 8192},
	)
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.TotalBytes > 8192 {
		t.Errorf("TotalBytes = %d, превышен лимит 8192", res.TotalBytes)
	}
	if !res.Truncated {
		t.Error("Truncated не выставлен при упоре в лимит объёма")
	}
}

func TestSingleFileMaxBytes(t *testing.T) {
	res, err := unpack.Artifact(
		zipBytes(t, map[string]string{"huge.txt": strings.Repeat("A", 5000), "small.txt": "ok"}),
		"x.zip",
		unpack.Limits{MaxFileBytes: 1024},
	)
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.SkippedLarge != 1 {
		t.Errorf("SkippedLarge = %d, ожидался 1", res.SkippedLarge)
	}
	if res.Files != 1 {
		t.Errorf("Files = %d, ожидался только small.txt", res.Files)
	}
}

// TestNestedArchiveExpanded — пакет, везущий в себе ещё один архив.
func TestNestedArchiveExpanded(t *testing.T) {
	inner := zipBytes(t, map[string]string{"inner/secret.py": "banner = 1\n"})
	var outer bytes.Buffer
	w := zip.NewWriter(&outer)
	f, err := w.Create("bundled.zip")
	if err != nil {
		t.Fatalf("zip.Create: %v", err)
	}
	if _, err := f.Write(inner); err != nil {
		t.Fatalf("запись вложенного архива: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("закрытие zip: %v", err)
	}

	res, err := unpack.Artifact(outer.Bytes(), "outer.zip", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	var found bool
	_ = filepath.Walk(res.Root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.Name() == "secret.py" {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("вложенный архив не раскрыт — secret.py не найден")
	}
}

// TestNestedDepthLimit — вложенность раскрывается не глубже MaxDepth.
func TestNestedDepthLimit(t *testing.T) {
	level2 := zipBytes(t, map[string]string{"deep.py": "x\n"})
	var level1 bytes.Buffer
	w1 := zip.NewWriter(&level1)
	f1, _ := w1.Create("level2.zip")
	_, _ = f1.Write(level2)
	_ = w1.Close()

	var level0 bytes.Buffer
	w0 := zip.NewWriter(&level0)
	f0, _ := w0.Create("level1.zip")
	_, _ = f0.Write(level1.Bytes())
	_ = w0.Close()

	res, err := unpack.Artifact(level0.Bytes(), "top.zip", unpack.Limits{MaxDepth: 1})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	var found bool
	_ = filepath.Walk(res.Root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.Name() == "deep.py" {
			found = true
		}
		return nil
	})
	if found {
		t.Error("раскрытие ушло глубже MaxDepth=1")
	}
}

// TestNotAnArchiveScannedAsFile — одиночный .py тоже надо просканировать, а не
// объявить «не архив, пропускаем».
func TestNotAnArchiveScannedAsFile(t *testing.T) {
	res, err := unpack.Artifact([]byte("print('hello')\n"), "script.py", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	defer unpack.Cleanup(res)

	if res.Files != 1 {
		t.Errorf("Files = %d, одиночный файл должен быть учтён", res.Files)
	}
	if got := read(t, filepath.Join(res.Root, "script.py")); got != "print('hello')\n" {
		t.Errorf("содержимое = %q", got)
	}
	if len(res.Notes) == 0 {
		t.Error("отсутствие архива не отражено в Notes")
	}
}

func TestCleanupRemovesEverything(t *testing.T) {
	res, err := unpack.Artifact(zipBytes(t, map[string]string{"a.py": "x"}), "a.zip", unpack.Limits{})
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	root := res.Root
	unpack.Cleanup(res)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("каталог %s не удалён", root)
	}
	unpack.Cleanup(res) // повторный вызов безопасен
}

// TestBrokenArchiveDoesNotFail — битый архив не роняет конвейер: решение о
// пакете принимает шаг, а не распаковщик.
func TestBrokenArchiveDoesNotFail(t *testing.T) {
	broken := append([]byte{0x1f, 0x8b}, []byte("это не gzip")...)
	res, err := unpack.Artifact(broken, "broken.tar.gz", unpack.Limits{})
	if err != nil {
		t.Fatalf("битый архив не должен возвращать ошибку: %v", err)
	}
	defer unpack.Cleanup(res)
	if len(res.Notes) == 0 {
		t.Error("битый архив не отражён в Notes")
	}
}
