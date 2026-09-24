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
	"net/url"
	"path"
	"strings"
)

const (
	mediaDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex           = "application/vnd.oci.image.index.v1+json"
	maxOCILayoutFiles       = 100000
)

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type ociLayoutIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

type ociDocument struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

type parsedOCILayout struct {
	root  ociDescriptor
	blobs map[string][]byte
}

func (g *Generic) dockerAPIBase(repo string) string {
	return fmt.Sprintf("%s/api/docker/%s/v2", strings.TrimRight(g.cfg.BaseURL, "/"), url.PathEscape(repo))
}

func escapedImage(name string) string {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func dockerTagAndDigest(version string) (tag, digest string) {
	tag, digest, _ = strings.Cut(strings.TrimSpace(version), "@")
	return strings.TrimSpace(tag), strings.TrimSpace(digest)
}

func (g *Generic) manifestURL(t Target, reference string) string {
	return fmt.Sprintf("%s/%s/manifests/%s", g.dockerAPIBase(t.Repo), escapedImage(t.Name),
		url.PathEscape(reference))
}

func (g *Generic) blobURL(t Target, digest string) string {
	return fmt.Sprintf("%s/%s/blobs/%s", g.dockerAPIBase(t.Repo), escapedImage(t.Name),
		url.PathEscape(digest))
}

// ociReference — ссылка для docker pull. /artifactory — REST-корень JFrog,
// но repository-path access у Docker идёт через <host>/<repo>/<image>.
func (g *Generic) ociReference(t Target) string {
	base := strings.TrimSuffix(strings.TrimRight(g.cfg.BaseURL, "/"), "/artifactory")
	tag, digest := dockerTagAndDigest(t.Version)
	ref := fmt.Sprintf("%s/%s/%s:%s", base, t.Repo, t.Name, tag)
	if digest != "" {
		ref += "@" + digest
	}
	return ref
}

func (g *Generic) ociExists(ctx context.Context, t Target) (bool, error) {
	tag, digest := dockerTagAndDigest(t.Version)
	reference := tag
	if digest != "" {
		reference = digest
	}
	resp, err := g.do(ctx, http.MethodHead, g.manifestURL(t, reference), nil,
		map[string]string{"Accept": strings.Join([]string{
			mediaOCIIndex, mediaDockerManifestList, mediaOCIManifest, mediaDockerManifest,
		}, ", ")})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, rejected(g.Kind(), t.Name+":"+reference, resp.StatusCode, body)
	}
	return true, nil
}

// PublishOCI разворачивает проверенный OCI layout в Docker Registry API
// Artifactory. Сначала загружаются content-addressable blobs, затем дочерние
// manifests и последним — исходный multi-platform index под пользовательским
// тегом. Его digest при этом остаётся тем самым index digest, который был
// указан в заявке.
func (g *Generic) PublishOCI(ctx context.Context, t Target, layoutTarGz []byte) (string, error) {
	if g.cfg.DryRun {
		return "", fmt.Errorf("OCI-публикация вызвана в режиме dry-run: это ошибка вызывающего кода")
	}
	layout, err := parseOCILayout(layoutTarGz)
	if err != nil {
		return "", err
	}
	_, requestedDigest := dockerTagAndDigest(t.Version)
	if requestedDigest != "" && !strings.EqualFold(requestedDigest, layout.root.Digest) {
		return "", fmt.Errorf("OCI layout содержит index %s вместо указанного в заявке %s",
			layout.root.Digest, requestedDigest)
	}

	order, manifestSet, err := manifestOrder(layout.root, layout.blobs)
	if err != nil {
		return "", err
	}
	for digest, body := range layout.blobs {
		if manifestSet[digest] {
			continue
		}
		if err := g.uploadBlob(ctx, t, digest, body); err != nil {
			return "", err
		}
	}

	// post-order: дочерние manifests уже существуют, когда публикуется index.
	for _, descriptor := range order {
		if descriptor.Digest == layout.root.Digest {
			continue
		}
		if err := g.putManifest(ctx, t, descriptor.Digest, descriptor, layout.blobs[descriptor.Digest]); err != nil {
			return "", err
		}
	}
	tag, _ := dockerTagAndDigest(t.Version)
	if err := g.putManifest(ctx, t, tag, layout.root, layout.blobs[layout.root.Digest]); err != nil {
		return "", err
	}
	return g.ociReference(t), nil
}

func parseOCILayout(payload []byte) (parsedOCILayout, error) {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return parsedOCILayout{}, fmt.Errorf("OCI layout не является tar.gz: %w", err)
	}
	defer gz.Close()

	files := make(map[string][]byte)
	tr := tar.NewReader(gz)
	for count := 0; count < maxOCILayoutFiles; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return parsedOCILayout{}, fmt.Errorf("OCI layout не разобран: %w", err)
		}
		name := path.Clean(h.Name)
		if h.Typeflag != tar.TypeReg || name == "." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
			return parsedOCILayout{}, fmt.Errorf("OCI layout содержит недопустимый путь %q", h.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return parsedOCILayout{}, fmt.Errorf("чтение %s из OCI layout: %w", name, err)
		}
		files[name] = body
	}

	var index ociLayoutIndex
	if err := json.Unmarshal(files["index.json"], &index); err != nil {
		return parsedOCILayout{}, fmt.Errorf("index.json OCI layout не разобран: %w", err)
	}
	if len(index.Manifests) != 1 {
		return parsedOCILayout{}, fmt.Errorf("в OCI layout ожидался один корневой index/manifest, получено %d",
			len(index.Manifests))
	}
	blobs := make(map[string][]byte)
	for name, body := range files {
		if !strings.HasPrefix(name, "blobs/") {
			continue
		}
		parts := strings.Split(name, "/")
		if len(parts) != 3 || parts[1] != "sha256" || len(parts[2]) != 64 {
			return parsedOCILayout{}, fmt.Errorf("некорректный путь blob в OCI layout: %s", name)
		}
		digest := "sha256:" + strings.ToLower(parts[2])
		sum := sha256.Sum256(body)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
			return parsedOCILayout{}, fmt.Errorf("blob %s в OCI layout имеет digest %s", digest, got)
		}
		blobs[digest] = body
	}
	if _, ok := blobs[index.Manifests[0].Digest]; !ok {
		return parsedOCILayout{}, fmt.Errorf("корневой manifest %s отсутствует в OCI layout",
			index.Manifests[0].Digest)
	}
	return parsedOCILayout{root: index.Manifests[0], blobs: blobs}, nil
}

func manifestOrder(root ociDescriptor, blobs map[string][]byte) ([]ociDescriptor, map[string]bool, error) {
	seen := make(map[string]bool)
	manifestSet := make(map[string]bool)
	var order []ociDescriptor
	var walk func(ociDescriptor) error
	walk = func(descriptor ociDescriptor) error {
		if seen[descriptor.Digest] {
			return nil
		}
		body, ok := blobs[descriptor.Digest]
		if !ok {
			return fmt.Errorf("manifest %s отсутствует в OCI layout", descriptor.Digest)
		}
		seen[descriptor.Digest] = true
		manifestSet[descriptor.Digest] = true
		var document ociDocument
		if err := json.Unmarshal(body, &document); err != nil {
			return fmt.Errorf("manifest %s не разобран: %w", descriptor.Digest, err)
		}
		if descriptor.MediaType == "" {
			descriptor.MediaType = document.MediaType
		}
		for _, child := range document.Manifests {
			if err := walk(child); err != nil {
				return err
			}
		}
		order = append(order, descriptor)
		return nil
	}
	if err := walk(root); err != nil {
		return nil, nil, err
	}
	return order, manifestSet, nil
}

func (g *Generic) uploadBlob(ctx context.Context, t Target, digest string, body []byte) error {
	head, err := g.do(ctx, http.MethodHead, g.blobURL(t, digest), nil, nil)
	if err != nil {
		return err
	}
	status := head.StatusCode
	head.Body.Close()
	if status == http.StatusOK {
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("Artifactory ответил %d на проверку OCI blob %s", status, digest)
	}

	startURL := fmt.Sprintf("%s/%s/blobs/uploads/", g.dockerAPIBase(t.Repo), escapedImage(t.Name))
	resp, err := g.do(ctx, http.MethodPost, startURL, nil, nil)
	if err != nil {
		return err
	}
	location := resp.Header.Get("Location")
	status = resp.StatusCode
	resp.Body.Close()
	if status < 200 || status >= 300 || location == "" {
		return fmt.Errorf("Artifactory не начал загрузку OCI blob %s: HTTP %d, Location=%q",
			digest, status, location)
	}
	base, _ := url.Parse(startURL)
	next, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("Artifactory вернул некорректный Location для blob %s: %w", digest, err)
	}
	next = base.ResolveReference(next)
	query := next.Query()
	query.Set("digest", digest)
	next.RawQuery = query.Encode()

	complete, err := g.do(ctx, http.MethodPut, next.String(), body,
		map[string]string{"Content-Type": "application/octet-stream"})
	if err != nil {
		return err
	}
	defer complete.Body.Close()
	if complete.StatusCode < 200 || complete.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(complete.Body, 1024))
		return rejected(g.Kind(), t.Name+"/blobs/"+digest, complete.StatusCode, raw)
	}
	return nil
}

func (g *Generic) putManifest(
	ctx context.Context, t Target, reference string, descriptor ociDescriptor, body []byte,
) error {
	mediaType := descriptor.MediaType
	if mediaType == "" {
		var document ociDocument
		if err := json.Unmarshal(body, &document); err != nil {
			return err
		}
		mediaType = document.MediaType
		if mediaType == "" && len(document.Manifests) > 0 {
			mediaType = mediaOCIIndex
		} else if mediaType == "" {
			mediaType = mediaOCIManifest
		}
	}
	resp, err := g.do(ctx, http.MethodPut, g.manifestURL(t, reference), body,
		map[string]string{"Content-Type": mediaType})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return rejected(g.Kind(), t.Name+"/manifests/"+reference, resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != "" &&
		!strings.EqualFold(got, descriptor.Digest) {
		return fmt.Errorf("Artifactory сохранил manifest как %s вместо %s", got, descriptor.Digest)
	}
	return nil
}

func (g *Generic) deleteOCI(ctx context.Context, t Target) (bool, error) {
	tag, digest := dockerTagAndDigest(t.Version)
	if digest == "" {
		resp, err := g.do(ctx, http.MethodHead, g.manifestURL(t, tag), nil,
			map[string]string{"Accept": strings.Join([]string{
				mediaOCIIndex, mediaDockerManifestList, mediaOCIManifest, mediaDockerManifest,
			}, ", ")})
		if err != nil {
			return false, err
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return false, nil
		}
		digest = resp.Header.Get("Docker-Content-Digest")
		resp.Body.Close()
		if digest == "" {
			return false, fmt.Errorf("Artifactory не сообщил digest Docker manifest %s:%s", t.Name, tag)
		}
	}
	resp, err := g.do(ctx, http.MethodDelete, g.manifestURL(t, digest), nil, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, rejected(g.Kind(), t.Name+"/manifests/"+digest, resp.StatusCode, raw)
	}
	return true, nil
}

var _ OCIPublisher = (*Generic)(nil)
