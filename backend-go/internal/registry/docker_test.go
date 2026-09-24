package registry_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"moderation/internal/registry"
)

// dockerRegistry — фейковый реестр образов.
//
// Полноценный, а не заглушка на один ответ: считает digest блобов сам,
// отвечает 401 с WWW-Authenticate, как это делает Docker Hub, и выдаёт токен.
// Тест, прошедший на нём, проверяет разбор манифеста и сборку раскладки, а не
// совпадение с подставным ответом.
type dockerRegistry struct {
	blobs     map[string][]byte // digest -> тело
	manifests map[string]string // ссылка (тег или digest) -> digest манифеста
	// requireToken — отвечать 401 на запрос без токена, как Docker Hub.
	requireToken bool
	tokenIssued  int
	// identityEncodingSeen подтверждает, что клиент запретил прозрачную
	// распаковку gzip-слоёв стандартным HTTP transport Go.
	identityEncodingSeen bool
}

func newDockerRegistry() *dockerRegistry {
	return &dockerRegistry{
		blobs:     map[string][]byte{},
		manifests: map[string]string{},
	}
}

func (d *dockerRegistry) put(body []byte) string {
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	d.blobs[digest] = body
	return digest
}

// tag связывает тег с манифестом.
func (d *dockerRegistry) tag(name string, body []byte) string {
	digest := d.put(body)
	d.manifests[name] = digest
	d.manifests[digest] = digest
	return digest
}

func (d *dockerRegistry) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()

	if strings.Contains(url, "/token") {
		d.tokenIssued++
		return jsonResponse(http.StatusOK, `{"token":"test-token"}`, nil), nil
	}
	if d.requireToken && req.Header.Get("Authorization") == "" {
		header := http.Header{}
		header.Set("WWW-Authenticate",
			`Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`)
		return jsonResponse(http.StatusUnauthorized, `{"errors":[]}`, header), nil
	}

	switch {
	case strings.Contains(url, "/manifests/"):
		ref := url[strings.LastIndex(url, "/manifests/")+len("/manifests/"):]
		digest, ok := d.manifests[ref]
		if !ok {
			return jsonResponse(http.StatusNotFound, `{"errors":[]}`, nil), nil
		}
		header := http.Header{}
		header.Set("Docker-Content-Digest", digest)
		return jsonResponse(http.StatusOK, string(d.blobs[digest]), header), nil

	case strings.Contains(url, "/blobs/"):
		if req.Header.Get("Accept-Encoding") == "identity" {
			d.identityEncodingSeen = true
		}
		digest := url[strings.LastIndex(url, "/blobs/")+len("/blobs/"):]
		body, ok := d.blobs[digest]
		if !ok {
			return jsonResponse(http.StatusNotFound, `{"errors":[]}`, nil), nil
		}
		return jsonResponse(http.StatusOK, string(body), nil), nil
	}
	return jsonResponse(http.StatusNotFound, `{"errors":[]}`, nil), nil
}

func jsonResponse(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     header,
	}
}

func dockerPlugin(t *testing.T, d *dockerRegistry) registry.Plugin {
	t.Helper()
	reg := registry.New(registry.Config{
		DockerURL: "https://registry.test", DockerAuthURL: "https://auth.test/token",
		DockerService: "registry.test", HTTP: d,
	})
	p, err := reg.Get("docker")
	if err != nil {
		t.Fatalf("Get(docker): %v", err)
	}
	return p
}

// singleImage кладёт в реестр образ одной платформы и возвращает digest его
// манифеста.
func singleImage(d *dockerRegistry, tag, created, license string) string {
	config, _ := json.Marshal(map[string]any{
		"created": created,
		"config": map[string]any{
			"Labels": map[string]string{"org.opencontainers.image.licenses": license},
		},
	})
	configDigest := d.put(config)
	layer := d.put([]byte("слой образа"))

	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"digest": configDigest, "size": len(config)},
		"layers":        []map[string]any{{"digest": layer, "size": 12}},
	})
	return d.tag(tag, manifest)
}

// TestDockerPinnedIndexDigest — пользователь может указать immutable-ссылку
// image:tag@index-digest. Тег остаётся человекочитаемым именем, но запрос к
// реестру и проверка выполняются по digest.
func TestDockerPinnedIndexDigest(t *testing.T) {
	d := newDockerRegistry()
	platformDigest := singleImage(d, "platform", "2024-01-15T10:00:00Z", "PostgreSQL")
	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest":    platformDigest,
			"platform":  map[string]string{"os": "linux", "architecture": "amd64"},
		}},
	})
	digest := d.tag("14.23", index)
	plugin := dockerPlugin(t, d)

	entry := "postgres:14.23@" + digest
	ref, err := registry.ParseEntry(plugin, entry)
	if err != nil {
		t.Fatalf("разбор pinned-ссылки %q: %v", entry, err)
	}
	if ref.Name != "library/postgres" || ref.Version != "14.23@"+digest {
		t.Fatalf("ссылка разобрана неверно: %+v", ref)
	}
	meta, err := plugin.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata по digest: %v", err)
	}
	if meta.Checksum != digest {
		t.Errorf("манифест = %q, ожидался закреплённый %q", meta.Checksum, digest)
	}
}

func TestDockerRejectsPlatformManifestAsIndexDigest(t *testing.T) {
	d := newDockerRegistry()
	manifestDigest := singleImage(d, "14.23", "2024-01-15T10:00:00Z", "PostgreSQL")
	plugin := dockerPlugin(t, d)
	ref, err := registry.ParseEntry(plugin, "postgres:14.23@"+manifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = plugin.FetchMetadata(context.Background(), ref)
	if err == nil || !strings.Contains(err.Error(), "manifest одной платформы") {
		t.Fatalf("platform manifest digest принят как index digest: %v", err)
	}
}

func TestDockerCorporatePublicationReference(t *testing.T) {
	plugin := dockerPlugin(t, newDockerRegistry())
	digest := "sha256:" + strings.Repeat("a", 64)
	ref, err := registry.ParseEntry(plugin, "postgres:14.23@"+digest)
	if err != nil {
		t.Fatal(err)
	}

	// Для внешнего Docker Hub имя нормализовано как library/postgres, но во
	// внутреннем JFrog корпоративный путь — docker/postgres/14.23.
	if got := registry.PublishedName(ref.Manager, ref.Name); got != "postgres" {
		t.Fatalf("PublishedName = %q, ожидался postgres", got)
	}
	want := "docker pull repo.ptsecurity.ru:443/docker/postgres:14.23@" + digest
	if got := plugin.InstallCommand(ref, "https://repo.ptsecurity.ru:443/artifactory", "docker"); got != want {
		t.Fatalf("InstallCommand = %q, ожидалась %q", got, want)
	}
	if got := plugin.ArtifactPath(ref, "image.oci.tar.gz"); !strings.HasPrefix(got, "postgres/") {
		t.Fatalf("ArtifactPath = %q, namespace library попал во внутренний путь", got)
	}

	if got := registry.PublishedName("docker", "bitnami/postgresql"); got != "bitnami/postgresql" {
		t.Fatalf("namespace стороннего издателя потерян: %q", got)
	}
	if got := registry.PublishedName("pypi", "library/example"); got != "library/example" {
		t.Fatalf("имя не-Docker пакета изменено: %q", got)
	}
}

// TestDockerMetadata — дата сборки и лицензия берутся из конфигурации образа,
// а digest манифеста фиксирует содержимое: тег можно переставить, digest — нет.
func TestDockerMetadata(t *testing.T) {
	d := newDockerRegistry()
	singleImage(d, "3.19", "2024-01-15T10:00:00Z", "MIT")
	plugin := dockerPlugin(t, d)

	ref, err := registry.ParseEntry(plugin, "alpine:3.19")
	if err != nil {
		t.Fatalf("разбор записи: %v", err)
	}
	meta, err := plugin.FetchMetadata(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if meta.PublishedAt == nil || meta.PublishedAt.Format("2006-01-02") != "2024-01-15" {
		t.Errorf("дата публикации = %v", meta.PublishedAt)
	}
	if meta.LicenseSPDX != "MIT" {
		t.Errorf("лицензия = %q, ожидалась MIT", meta.LicenseSPDX)
	}
	if !strings.HasPrefix(meta.Checksum, "sha256:") || meta.ChecksumAlgo != "oci-digest" {
		t.Errorf("digest манифеста = %s/%s", meta.ChecksumAlgo, meta.Checksum)
	}
	// ArtifactURL пустой намеренно: образ одним GET не скачать, этим занимается
	// Downloader. Непустое значение здесь означало бы, что шаг скачивания
	// пойдёт не тем путём.
	if meta.ArtifactURL != "" {
		t.Errorf("ArtifactURL = %q, у docker он обязан быть пустым", meta.ArtifactURL)
	}
}

// TestDockerAnonymousToken — реестр отвечает 401 даже на публичный образ, и
// без получения анонимного токена Docker Hub недоступен вовсе.
func TestDockerAnonymousToken(t *testing.T) {
	d := newDockerRegistry()
	d.requireToken = true
	singleImage(d, "3.19", "2024-01-15T10:00:00Z", "MIT")
	plugin := dockerPlugin(t, d)

	ref, _ := registry.ParseEntry(plugin, "alpine:3.19")
	if _, err := plugin.FetchMetadata(context.Background(), ref); err != nil {
		t.Fatalf("FetchMetadata с токеном: %v", err)
	}
	if d.tokenIssued == 0 {
		t.Error("токен не запрашивался — на реестре, требующем авторизации, это 401 на каждом образе")
	}
}

// TestDockerDownloadBuildsOCILayout — скачанный образ разворачивается в
// стандартную OCI-раскладку: её принимают skopeo, podman и crane.
func TestDockerDownloadBuildsOCILayout(t *testing.T) {
	d := newDockerRegistry()
	singleImage(d, "3.19", "2024-01-15T10:00:00Z", "Apache-2.0")
	plugin := dockerPlugin(t, d)

	downloader, ok := plugin.(registry.Downloader)
	if !ok {
		t.Fatal("плагин docker обязан реализовывать Downloader")
	}
	ref, _ := registry.ParseEntry(plugin, "alpine:3.19")
	payload, filename, err := downloader.Download(context.Background(), ref, 10<<20)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !strings.HasSuffix(filename, ".oci.tar.gz") {
		t.Errorf("имя файла = %q", filename)
	}

	files := unpackTarGz(t, payload)
	if string(files["oci-layout"]) != `{"imageLayoutVersion":"1.0.0"}` {
		t.Errorf("oci-layout = %q", files["oci-layout"])
	}
	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(files["index.json"], &index); err != nil {
		t.Fatalf("index.json не разобран: %v", err)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("манифестов в index.json: %d", len(index.Manifests))
	}
	// Тег в аннотации: без него инструменты загружают образ безымянным, и
	// «docker images» показывает <none>:<none>.
	if index.Manifests[0].Annotations["org.opencontainers.image.ref.name"] != "3.19" {
		t.Errorf("тег в index.json = %v", index.Manifests[0].Annotations)
	}

	// Манифест, конфигурация и слой — все на месте и лежат по своим digest.
	blobs := 0
	for name, body := range files {
		if !strings.HasPrefix(name, "blobs/sha256/") {
			continue
		}
		blobs++
		sum := sha256.Sum256(body)
		if want := strings.TrimPrefix(name, "blobs/sha256/"); hex.EncodeToString(sum[:]) != want {
			t.Errorf("блоб %s лежит не по своему digest", name)
		}
	}
	if blobs != 3 {
		t.Errorf("блобов в архиве: %d, ожидалось 3 (манифест, конфигурация, слой)", blobs)
	}
	if !d.identityEncodingSeen {
		t.Error("blob запрошен без Accept-Encoding: identity — gzip-слой может быть распакован до проверки digest")
	}
}

// TestDockerDownloadTakesAllPlatforms — у multiarch-образа скачиваются ВСЕ
// платформы.
//
// Взять одну значило бы промодерировать amd64 и пустить в контур
// непроверенный arm64 под тем же именем: образ по тегу один, и разделить
// решение по платформам после публикации уже нельзя.
func TestDockerDownloadTakesAllPlatforms(t *testing.T) {
	d := newDockerRegistry()

	platform := func(os, arch, layer string) (string, int) {
		// Архитектура в конфигурации разная — как и в настоящем образе. Если
		// сделать её одинаковой, блобы конфигураций совпадут и схлопнутся
		// дедупликацией, и тест перестанет проверять то, ради чего написан.
		config, _ := json.Marshal(map[string]any{
			"created": "2024-01-15T10:00:00Z", "os": os, "architecture": arch,
		})
		configDigest := d.put(config)
		layerDigest := d.put([]byte(layer))
		manifest, _ := json.Marshal(map[string]any{
			"schemaVersion": 2,
			"mediaType":     "application/vnd.oci.image.manifest.v1+json",
			"config":        map[string]any{"digest": configDigest, "size": len(config)},
			"layers":        []map[string]any{{"digest": layerDigest, "size": len(layer)}},
		})
		digest := d.put(manifest)
		d.manifests[digest] = digest
		return digest, len(manifest)
	}
	amd64Digest, amd64Size := platform("linux", "amd64", "слой amd64")
	armDigest, armSize := platform("linux", "arm64", "слой arm64")

	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{
			{"digest": amd64Digest, "size": amd64Size,
				"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
			{"digest": armDigest, "size": armSize,
				"platform": map[string]string{"os": "linux", "architecture": "arm64"}},
		},
	})
	d.tag("3.19", index)

	plugin := dockerPlugin(t, d)
	ref, _ := registry.ParseEntry(plugin, "alpine:3.19")
	payload, _, err := plugin.(registry.Downloader).Download(context.Background(), ref, 10<<20)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}

	files := unpackTarGz(t, payload)
	// index + два манифеста платформ + две конфигурации + два слоя.
	blobs := 0
	for name := range files {
		if strings.HasPrefix(name, "blobs/sha256/") {
			blobs++
		}
	}
	if blobs != 7 {
		t.Errorf("блобов в архиве: %d, ожидалось 7 — часть платформ не скачана", blobs)
	}
	for _, digest := range []string{amd64Digest, armDigest} {
		name := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
		if _, ok := files[name]; !ok {
			t.Errorf("манифест платформы %s отсутствует в архиве", digest)
		}
	}
}

// TestDockerDownloadIsReproducible — два прогона по одному образу дают
// побайтово одинаковый архив.
//
// Иначе sha256 артефакта менялся бы от прогона к прогону, и сверять то, что
// промодерировали, с тем, что опубликовали, было бы не с чем.
func TestDockerDownloadIsReproducible(t *testing.T) {
	d := newDockerRegistry()
	singleImage(d, "3.19", "2024-01-15T10:00:00Z", "MIT")
	plugin := dockerPlugin(t, d)
	ref, _ := registry.ParseEntry(plugin, "alpine:3.19")

	first, _, err := plugin.(registry.Downloader).Download(context.Background(), ref, 10<<20)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := plugin.(registry.Downloader).Download(context.Background(), ref, 10<<20)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hashOf(first)) != hex.EncodeToString(hashOf(second)) {
		t.Error("два прогона дали разные байты — sha256 артефакта не воспроизводится")
	}
}

// TestDockerRejectsCorruptedBlob — блоб, не соответствующий своему digest, не
// принимается: это то, что запустится, и брать его на веру нельзя.
func TestDockerRejectsCorruptedBlob(t *testing.T) {
	d := newDockerRegistry()
	singleImage(d, "3.19", "2024-01-15T10:00:00Z", "MIT")
	// Подменяем содержимое одного блоба, оставив его под прежним digest.
	for digest, body := range d.blobs {
		if string(body) == "слой образа" {
			d.blobs[digest] = []byte("подменённый слой")
			break
		}
	}

	plugin := dockerPlugin(t, d)
	ref, _ := registry.ParseEntry(plugin, "alpine:3.19")
	_, _, err := plugin.(registry.Downloader).Download(context.Background(), ref, 10<<20)
	if err == nil {
		t.Fatal("подменённый блоб принят — проверка digest не работает")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("ошибка не объясняет причину: %v", err)
	}
}

// TestDockerDownloadRespectsLimit — предел размера проверяется ДО упаковки:
// образ на десятки гигабайт не должен сначала оказаться в памяти целиком.
func TestDockerDownloadRespectsLimit(t *testing.T) {
	d := newDockerRegistry()
	singleImage(d, "3.19", "2024-01-15T10:00:00Z", "MIT")
	plugin := dockerPlugin(t, d)
	ref, _ := registry.ParseEntry(plugin, "alpine:3.19")

	_, _, err := plugin.(registry.Downloader).Download(context.Background(), ref, 8)
	if err == nil {
		t.Fatal("образ больше предела скачан целиком")
	}
	if !strings.Contains(err.Error(), "предел") {
		t.Errorf("ошибка не называет причину: %v", err)
	}
}

// TestDockerMissingTag — несуществующий тег отличается от недоступного
// реестра: первое ошибка пользователя, второе повод повторить.
func TestDockerMissingTag(t *testing.T) {
	d := newDockerRegistry()
	singleImage(d, "3.19", "2024-01-15T10:00:00Z", "MIT")
	plugin := dockerPlugin(t, d)

	ref, _ := registry.ParseEntry(plugin, "alpine:3.20")
	_, err := plugin.FetchMetadata(context.Background(), ref)
	if err == nil {
		t.Fatal("несуществующий тег принят")
	}
}

// --------------------------------------------------------------------- вспомогательное

func unpackTarGz(t *testing.T, payload []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("архив не распаковывается: %v", err)
	}
	defer gz.Close()

	files := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatalf("чтение архива: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("чтение файла %s: %v", header.Name, err)
		}
		files[header.Name] = body
	}
}

func hashOf(body []byte) []byte {
	sum := sha256.Sum256(body)
	return sum[:]
}
