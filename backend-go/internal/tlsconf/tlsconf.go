// Package tlsconf extends the process trust store with corporate root and
// intermediate CA certificates. The additional roots are added to the system
// pool; public certificate authorities remain trusted.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var certificateExtensions = map[string]bool{
	".cer": true,
	".crt": true,
	".pem": true,
}

// Install loads PEM certificates from files and one-level directories listed
// in paths. Entries may be separated by a comma or the operating system path
// list separator. An empty value or empty directory is a no-op.
//
// Invalid configured paths and files fail closed during service startup. This
// makes a CA deployment error visible immediately instead of presenting later
// as an opaque OIDC "certificate signed by unknown authority" error.
func Install(paths string) (int, error) {
	files, err := collect(paths)
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return 0, fmt.Errorf("чтение системного пула сертификатов: %w", err)
	}

	added := 0
	for _, filename := range files {
		contents, err := os.ReadFile(filename)
		if err != nil {
			return 0, err
		}
		count, err := appendPEM(pool, contents)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", filename, err)
		}
		added += count
	}
	if added == 0 {
		return 0, fmt.Errorf("не найдено ни одного сертификата по пути %q", paths)
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return 0, fmt.Errorf("http.DefaultTransport не является *http.Transport")
	}
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	tlsConfig.RootCAs = pool
	transport.TLSClientConfig = tlsConfig
	return added, nil
}

func collect(paths string) ([]string, error) {
	var files []string
	for _, path := range splitPaths(paths) {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !certificateExtensions[strings.ToLower(filepath.Ext(entry.Name()))] {
				continue
			}
			files = append(files, filepath.Join(path, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func splitPaths(paths string) []string {
	fields := strings.FieldsFunc(paths, func(r rune) bool {
		return r == ',' || r == os.PathListSeparator
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out
}

func appendPEM(pool *x509.CertPool, contents []byte) (int, error) {
	count := 0
	for len(contents) > 0 {
		var block *pem.Block
		block, contents = pem.Decode(contents)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return count, fmt.Errorf("разбор сертификата: %w", err)
		}
		pool.AddCert(certificate)
		count++
	}
	if count == 0 {
		return 0, fmt.Errorf("не найдено ни одного PEM-блока CERTIFICATE")
	}
	return count, nil
}
