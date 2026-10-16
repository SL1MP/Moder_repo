package dragon

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
)

func TestPrepareArchiveConvertsTarballToScannableZip(t *testing.T) {
	var source bytes.Buffer
	gz := gzip.NewWriter(&source)
	tw := tar.NewWriter(gz)
	content := []byte("package contents")
	if err := tw.WriteHeader(&tar.Header{Name: "package/index.js", Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareArchive(source.Bytes(), "package.tgz", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Filename != "package.zip" {
		t.Fatalf("filename = %q", prepared.Filename)
	}
	zr, err := zip.NewReader(bytes.NewReader(prepared.Payload), int64(len(prepared.Payload)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "package/index.js" {
		t.Fatalf("файлы ZIP: %+v", zr.File)
	}
	r, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("содержимое = %q, ошибка %v", got, err)
	}
	sum := sha256.Sum256(prepared.Payload)
	if prepared.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("SHA-256 архива Dragon не совпал")
	}
}

func TestPrepareArchivePreservesZipAndRejectsTarEscape(t *testing.T) {
	var source bytes.Buffer
	writer := zip.NewWriter(&source)
	f, err := writer.Create("package.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("{}"))
	_ = writer.Close()
	prepared, err := PrepareArchive(source.Bytes(), "package.whl", 1024)
	if err != nil || !bytes.Equal(prepared.Payload, source.Bytes()) {
		t.Fatalf("wheel изменён: %v", err)
	}
	var tarball bytes.Buffer
	tw := tar.NewWriter(&tarball)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape", Size: 1, Mode: 0644})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	if _, err := PrepareArchive(tarball.Bytes(), "bad.tar", 1024); err == nil {
		t.Fatal("tar с выходом за каталог принят")
	}
}
