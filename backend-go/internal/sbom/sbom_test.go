package sbom

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPackageManagersProduceCanonicalCycloneDX(t *testing.T) {
	cases := []struct{ manager, name, version, wantPURL string }{
		{"pypi", "requests", "2.32.3", "pkg:pypi/requests@2.32.3"},
		{"npm", "@scope/pkg", "1.2.0", "pkg:npm/%40scope/pkg@1.2.0"},
		{"nuget", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{"maven", "org.example:demo", "1.0.0", "pkg:maven/org.example/demo@1.0.0"},
		{"go", "github.com/acme/mod", "v1.4.0", "pkg:golang/github.com/acme/mod@v1.4.0"},
		{"conan", "boost", "1.91.0", "pkg:conan/boost@1.91.0"},
	}
	g := DefaultGenerator{Now: func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }}
	for _, tc := range cases {
		t.Run(tc.manager, func(t *testing.T) {
			docs, err := g.Generate(context.Background(), Input{
				Manager: tc.manager, Name: tc.name, Version: tc.version, RawVersion: tc.version,
				LicenseSPDX: "MIT", ArtifactSHA256: strings.Repeat("a", 64),
			})
			if err != nil { t.Fatal(err) }
			if len(docs) != 1 { t.Fatalf("документов = %d", len(docs)) }
			var body map[string]any
			if err := json.Unmarshal(docs[0].Body, &body); err != nil { t.Fatal(err) }
			if body["bomFormat"] != "CycloneDX" || body["specVersion"] != "1.4" {
				t.Fatalf("не CycloneDX 1.4: %s", docs[0].Body)
			}
			metadata := body["metadata"].(map[string]any)
			component := metadata["component"].(map[string]any)
			if component["purl"] != tc.wantPURL {
				t.Errorf("purl = %q, ожидался %q", component["purl"], tc.wantPURL)
			}
			components := body["components"].([]any)
			if len(components) != 1 { t.Fatalf("components = %d", len(components)) }
		})
	}
}

func TestDockerProducesDocumentPerPlatformAndSkipsAttestation(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "calls.log")
	syft := filepath.Join(dir, "syft")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + logFile + "\"\n" +
		"printf '%s' '{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.4\",\"version\":1,\"metadata\":{},\"components\":[]}'\n"
	if err := os.WriteFile(syft, []byte(script), 0o755); err != nil { t.Fatal(err) }

	payload := dockerLayout(t)
	docs, err := (DefaultGenerator{SyftBinary: syft}).Generate(context.Background(), Input{
		Manager: "docker", Name: "library/postgres",
		Version: "14.23@sha256:" + strings.Repeat("f", 64),
		RawVersion: "14.23@sha256:" + strings.Repeat("f", 64), Payload: payload,
	})
	if err != nil { t.Fatal(err) }
	if len(docs) != 2 { t.Fatalf("документов = %d, ожидалось две платформы", len(docs)) }
	if docs[0].Platform != "linux/amd64" || docs[1].Platform != "linux/arm64/v8" {
		t.Fatalf("платформы = %q, %q", docs[0].Platform, docs[1].Platform)
	}
	for _, doc := range docs {
		if !bytes.Contains(doc.Body, []byte(`"type": "container"`)) ||
			!bytes.Contains(doc.Body, []byte(`pkg:oci/postgres@sha256`)) {
			t.Errorf("корневой компонент Docker не нормализован: %s", doc.Body)
		}
	}
	calls, err := os.ReadFile(logFile)
	if err != nil { t.Fatal(err) }
	if lines := strings.Count(strings.TrimSpace(string(calls)), "\n") + 1; lines != 2 {
		t.Errorf("Syft вызван %d раз, ожидалось 2", lines)
	}
}

func TestDockerRepositoryNormalization(t *testing.T) {
	cases := []struct{ input, repository, name string }{
		{"postgres", "index.docker.io/library/postgres", "postgres"},
		{"library/postgres", "index.docker.io/library/postgres", "postgres"},
		{"mcr.microsoft.com/dotnet/aspnet", "mcr.microsoft.com/dotnet/aspnet", "dotnet/aspnet"},
		{"registry.example:5000/team/app", "registry.example:5000/team/app", "team/app"},
	}
	for _, tc := range cases {
		repository, name := dockerRepository(tc.input)
		if repository != tc.repository || name != tc.name {
			t.Errorf("dockerRepository(%q) = (%q, %q), ожидалось (%q, %q)",
				tc.input, repository, name, tc.repository, tc.name)
		}
	}
}

func dockerLayout(t *testing.T) []byte {
	t.Helper()
	rootDigest := "sha256:" + strings.Repeat("0", 64)
	amd := "sha256:" + strings.Repeat("1", 64)
	arm := "sha256:" + strings.Repeat("2", 64)
	att := "sha256:" + strings.Repeat("3", 64)
	root, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{
			{"digest": arm, "platform": map[string]string{"os": "linux", "architecture": "arm64", "variant": "v8"}},
			{"digest": amd, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
			{"digest": att, "platform": map[string]string{"os": "unknown", "architecture": "unknown"},
				"annotations": map[string]string{"vnd.docker.reference.type": "attestation-manifest"}},
		},
	})
	layoutIndex, _ := json.Marshal(map[string]any{"manifests": []map[string]any{{"digest": rootDigest}}})
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json": layoutIndex,
		"blobs/sha256/" + strings.TrimPrefix(rootDigest, "sha256:"): root,
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil { t.Fatal(err) }
		if _, err := tw.Write(body); err != nil { t.Fatal(err) }
	}
	if err := tw.Close(); err != nil { t.Fatal(err) }
	if err := gz.Close(); err != nil { t.Fatal(err) }
	return buf.Bytes()
}
