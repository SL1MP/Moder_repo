package registry

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Сборка образа в OCI-раскладку.
//
// Раскладка стандартная (github.com/opencontainers/image-spec, image-layout):
//
//	oci-layout            — версия раскладки
//	index.json            — что в архиве лежит и под каким тегом
//	blobs/sha256/<hex>    — манифесты, конфигурации и слои, по одному файлу
//
// Такой архив принимают skopeo, podman, crane и docker load (через skopeo
// copy). Альтернатива — формат `docker save` — не стандартизована и у разных
// версий docker отличается, а нам нужно, чтобы то же самое открылось и в
// песочнице, и у разработчика.
type ociLayout struct {
	blobs map[string][]byte
	index ociIndex
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func newOCILayout() *ociLayout {
	return &ociLayout{
		blobs: make(map[string][]byte),
		index: ociIndex{SchemaVersion: 2, MediaType: mediaOCIIndex},
	}
}

func (l *ociLayout) has(digest string) bool {
	_, ok := l.blobs[digest]
	return ok
}

func (l *ociLayout) addBlob(digest string, body []byte) {
	if digest == "" {
		return
	}
	l.blobs[digest] = body
}

// addRoot записывает в index.json, с чего образ начинается, и под каким тегом.
// Без аннотации с тегом инструменты загружают образ безымянным, и «docker
// images» показывает <none>:<none>.
func (l *ociLayout) addRoot(mediaType, digest string, size int64, tag string) {
	l.index.Manifests = append(l.index.Manifests, ociDescriptor{
		MediaType: mediaType, Digest: digest, Size: size,
		Annotations: map[string]string{"org.opencontainers.image.ref.name": tag},
	})
}

// tarGz упаковывает раскладку.
//
// Файлы идут в отсортированном порядке и с нулевым временем: иначе два
// прогона по одному и тому же образу давали бы разные байты и разный sha256,
// и сверять артефакт было бы не с чем.
func (l *ociLayout) tarGz(limit int64) ([]byte, error) {
	indexBody, err := json.Marshal(l.index)
	if err != nil {
		return nil, fmt.Errorf("сборка index.json образа: %w", err)
	}

	files := map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json": indexBody,
	}
	for digest, body := range l.blobs {
		algo, hex, ok := strings.Cut(digest, ":")
		if !ok {
			// Digest без алгоритма — испорченный манифест; класть такой блоб
			// некуда, и молча его терять нельзя.
			return nil, fmt.Errorf("digest %q записан без алгоритма", digest)
		}
		files[fmt.Sprintf("blobs/%s/%s", algo, hex)] = body
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf limitedBuffer
	buf.limit = limit
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.data, buf.err
}
