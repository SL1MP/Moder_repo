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
	target := Target{Repo: "docker-internal", Manager: "docker", Name: "library/postgres",
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
	if strings.Contains(published, "/artifactory/") || !strings.Contains(published, "/docker-internal/library/postgres:14.23@") {
		t.Errorf("ссылка docker pull сформирована неверно: %s", published)
	}
}
