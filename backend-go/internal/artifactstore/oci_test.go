package artifactstore

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testOCILayout(t *testing.T) ([]byte, string) {
	t.Helper()
	blobs := map[string][]byte{}
	add := func(body []byte) string {
		digest := digestOf(body)
		blobs[digest] = body
		return digest
	}
	platform := func(arch string) (string, int) {
		config := []byte(fmt.Sprintf(`{"architecture":%q,"os":"linux"}`, arch))
		configDigest := add(config)
		layer := []byte("layer-" + arch)
		layerDigest := add(layer)
		manifest, _ := json.Marshal(map[string]any{
			"schemaVersion": 2, "mediaType": mediaOCIManifest,
			"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json",
				"digest": configDigest, "size": len(config)},
			"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
				"digest": layerDigest, "size": len(layer)}},
		})
		return add(manifest), len(manifest)
	}
	amd64, amd64Size := platform("amd64")
	arm64, arm64Size := platform("arm64")
	indexBody, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaOCIIndex,
		"manifests": []map[string]any{
			{"mediaType": mediaOCIManifest, "digest": amd64, "size": amd64Size,
				"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
			{"mediaType": mediaOCIManifest, "digest": arm64, "size": arm64Size,
				"platform": map[string]string{"os": "linux", "architecture": "arm64"}},
		},
	})
	indexDigest := add(indexBody)
	layoutIndex, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaOCIIndex,
		"manifests": []map[string]any{{"mediaType": mediaOCIIndex,
			"digest": indexDigest, "size": len(indexBody)}},
	})

	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	write := func(name string, body []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	write("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	write("index.json", layoutIndex)
	for digest, body := range blobs {
		write("blobs/sha256/"+strings.TrimPrefix(digest, "sha256:"), body)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), indexDigest
}

func TestGenericPublishesEveryPlatformAsNativeOCI(t *testing.T) {
	layout, indexDigest := testOCILayout(t)
	uploadedBlobs := map[string][]byte{}
	uploadedManifests := map[string][]byte{}
	manifestTypes := map[string]string{}
	uploadID := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/library/postgres/") {
			t.Errorf("официальный образ опубликован с внешним namespace library: %s", r.URL.Path)
		}
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/blobs/"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/blobs/uploads/"):
			uploadID++
			w.Header().Set("Location", fmt.Sprintf("/upload/%d", uploadID))
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/upload/"):
			body, _ := io.ReadAll(r.Body)
			uploadedBlobs[r.URL.Query().Get("digest")] = body
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/"):
			body, _ := io.ReadAll(r.Body)
			reference := r.URL.Path[strings.LastIndex(r.URL.Path, "/manifests/")+len("/manifests/"):]
			uploadedManifests[reference] = body
			manifestTypes[reference] = r.Header.Get("Content-Type")
			w.Header().Set("Docker-Content-Digest", digestOf(body))
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("неожиданный запрос: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store, err := New(Config{Kind: KindGeneric, BaseURL: srv.URL + "/artifactory", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Repo: "docker-internal", Manager: "docker", Name: "postgres",
		DisplayName: "postgres", Version: "14.23@" + indexDigest}
	published, err := store.(OCIPublisher).PublishOCI(context.Background(), target, layout)
	if err != nil {
		t.Fatalf("PublishOCI: %v", err)
	}
	if len(uploadedBlobs) != 4 {
		t.Errorf("загружено blobs: %d, ожидалось 4 config/layer для двух платформ", len(uploadedBlobs))
	}
	if len(uploadedManifests) != 3 {
		t.Errorf("загружено manifests: %d, ожидалось два platform manifest и один index", len(uploadedManifests))
	}
	if got := digestOf(uploadedManifests["14.23"]); got != indexDigest {
		t.Errorf("под тегом опубликован %s вместо исходного index digest %s", got, indexDigest)
	}
	if manifestTypes["14.23"] != mediaOCIIndex {
		t.Errorf("Content-Type корня = %q, ожидался OCI index", manifestTypes["14.23"])
	}
	if strings.Contains(published, "/artifactory/") || !strings.Contains(published, "/docker-internal/postgres:14.23@") {
		t.Errorf("ссылка docker pull сформирована неверно: %s", published)
	}
}

func TestNexusPublishesEveryPlatformWithSkopeoAll(t *testing.T) {
	layout, indexDigest := testOCILayout(t)
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	authFile := filepath.Join(dir, "auth.json")
	runtimeFile := filepath.Join(dir, "runtime")
	script := filepath.Join(dir, "skopeo")
	if err := os.WriteFile(script, []byte(`#!/bin/sh
printf '%s\n' "$@" > "$FAKE_SKOPEO_ARGS"
if [ -n "$REGISTRY_AUTH_FILE" ]; then cp "$REGISTRY_AUTH_FILE" "$FAKE_SKOPEO_AUTH"; fi
printf '%s' "$XDG_RUNTIME_DIR" > "$FAKE_SKOPEO_RUNTIME"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SKOPEO_ARGS", argsFile)
	t.Setenv("FAKE_SKOPEO_AUTH", authFile)
	t.Setenv("FAKE_SKOPEO_RUNTIME", runtimeFile)

	store, err := New(Config{
		Kind: KindNexus, BaseURL: "http://nexus:8081",
		DockerRegistryURL: "http://nexus:8081/docker-internal",
		DockerPublicURL:   "https://packages.example/docker-internal",
		Username:          "moderation", Password: "secret", SkopeoBinary: script,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Repo: "docker-internal", Manager: "docker", Name: "postgres",
		DisplayName: "postgres", Version: "14.23@" + indexDigest}
	published, err := store.(OCIPublisher).PublishOCI(context.Background(), target, layout)
	if err != nil {
		t.Fatalf("PublishOCI: %v", err)
	}
	want := "https://packages.example/docker-internal/postgres:14.23@" + indexDigest
	if published != want {
		t.Fatalf("published = %q, ожидался %q", published, want)
	}
	rawArgs, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := string(rawArgs)
	for _, required := range []string{
		"copy\n", "--all\n", "--preserve-digests\n", "--dest-tls-verify=false\n",
		"docker://nexus:8081/docker-internal/postgres:14.23\n",
	} {
		if !strings.Contains(args, required) {
			t.Errorf("в аргументах skopeo нет %q:\n%s", required, args)
		}
	}
	if strings.Contains(args, "library/postgres") || strings.Contains(args, "secret") {
		t.Errorf("в destination попал внешний namespace или секрет: %s", args)
	}
	if !strings.Contains(args, "oci:/tmp/moderation-oci-") || strings.Contains(args, "oci-archive:") {
		t.Errorf("источник должен быть распакованным OCI layout без chown, аргументы:\n%s", args)
	}
	rawAuth, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawAuth), "secret") || !strings.Contains(string(rawAuth), "nexus:8081") {
		t.Errorf("auth-файл сформирован небезопасно или для неверного registry: %s", rawAuth)
	}
	runtimeDir, err := os.ReadFile(runtimeFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runtimeDir), "moderation-skopeo-runtime-") {
		t.Errorf("skopeo не получил доступный XDG_RUNTIME_DIR: %q", runtimeDir)
	}
}

func TestWriteOCILayoutDirectoryDoesNotRestoreTarOwnership(t *testing.T) {
	payload, _ := testOCILayout(t) // заголовки tar имеют uid/gid=0
	dir, cleanup, err := writeOCILayoutDirectory(payload)
	if err != nil {
		t.Fatalf("writeOCILayoutDirectory: %v", err)
	}
	defer cleanup()
	for _, name := range []string{"oci-layout", "index.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s не распакован: %v", name, err)
		}
		if !info.Mode().IsRegular() {
			t.Errorf("%s имеет тип %s, ожидался обычный файл", name, info.Mode())
		}
	}
}
