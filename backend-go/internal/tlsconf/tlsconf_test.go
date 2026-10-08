package tlsconf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCA(t *testing.T, path, commonName string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func preserveDefaultTransport(t *testing.T) {
	t.Helper()
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport не является *http.Transport")
	}
	previous := transport.TLSClientConfig
	t.Cleanup(func() { transport.TLSClientConfig = previous })
}

func TestInstallEmptyIsNoop(t *testing.T) {
	if count, err := Install(""); err != nil || count != 0 {
		t.Fatalf("Install(empty) = %d, %v; want 0, nil", count, err)
	}
	if count, err := Install(t.TempDir()); err != nil || count != 0 {
		t.Fatalf("Install(empty directory) = %d, %v; want 0, nil", count, err)
	}
}

func TestInstallAddsFileAndDirectoryCertificates(t *testing.T) {
	preserveDefaultTransport(t)
	directory := t.TempDir()
	writeTestCA(t, filepath.Join(directory, "root.crt"), "test-root")
	writeTestCA(t, filepath.Join(directory, "issuer.pem"), "test-issuer")
	if err := os.WriteFile(filepath.Join(directory, "README.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	count, err := Install(directory)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("Install(directory) = %d; want 2", count)
	}

	transport := http.DefaultTransport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("дополнительный trust store не установлен")
	}
}

func TestInstallRejectsInvalidConfiguration(t *testing.T) {
	preserveDefaultTransport(t)
	if _, err := Install(filepath.Join(t.TempDir(), "missing.crt")); err == nil {
		t.Fatal("для отсутствующего пути ожидалась ошибка")
	}

	invalid := filepath.Join(t.TempDir(), "invalid.crt")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(invalid); err == nil {
		t.Fatal("для файла без сертификата ожидалась ошибка")
	}
}
