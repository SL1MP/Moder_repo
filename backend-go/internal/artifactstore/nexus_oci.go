package artifactstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Nexus публикует Docker-образы через стандартный Registry API. Компонентный
// REST API Nexus для этого не подходит: загруженный им .oci.tar.gz останется
// обычным файлом, который docker pull не видит. skopeo делает тот же перенос,
// что принят в корпоративном скрипте: --all копирует index/list, manifests
// всех платформ, configs и layers.

func (n *Nexus) nexusDockerPrefix(t Target, public bool) (string, bool, error) {
	raw := n.cfg.DockerRegistryURL
	if public && n.cfg.DockerPublicURL != "" {
		raw = n.cfg.DockerPublicURL
	}
	if raw == "" {
		raw = strings.TrimRight(n.cfg.BaseURL, "/") + "/" + strings.Trim(t.Repo, "/")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false, fmt.Errorf(
			"адрес Docker Registry Nexus %q некорректен: ожидается http(s)://host[/repository]", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", false, fmt.Errorf("адрес Docker Registry Nexus не должен содержать query или fragment: %q", raw)
	}
	prefix := u.Host + strings.TrimRight(u.EscapedPath(), "/")
	if public {
		return u.Scheme + "://" + prefix, u.Scheme == "http", nil
	}
	return prefix, u.Scheme == "http", nil
}

func (n *Nexus) nexusDockerImage(t Target, public bool) (string, bool, error) {
	prefix, insecure, err := n.nexusDockerPrefix(t, public)
	if err != nil {
		return "", false, err
	}
	name := strings.Trim(t.Name, "/")
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, "@:\\") {
		return "", false, fmt.Errorf("имя Docker-образа %q нельзя опубликовать в Nexus", t.Name)
	}
	return prefix + "/" + name, insecure, nil
}

func (n *Nexus) nexusOCIReference(t Target) string {
	image, _, err := n.nexusDockerImage(t, true)
	if err != nil {
		return ""
	}
	tag, digest := dockerTagAndDigest(t.Version)
	ref := image + ":" + tag
	if digest != "" {
		ref += "@" + digest
	}
	return ref
}

func (n *Nexus) nexusTransportReference(t Target, byDigest bool) (string, bool, error) {
	image, insecure, err := n.nexusDockerImage(t, false)
	if err != nil {
		return "", false, err
	}
	tag, digest := dockerTagAndDigest(t.Version)
	if byDigest && digest != "" {
		return "docker://" + image + "@" + digest, insecure, nil
	}
	if tag == "" {
		return "", false, fmt.Errorf("для Docker-образа %s не указан tag", t.DisplayName)
	}
	return "docker://" + image + ":" + tag, insecure, nil
}

func (n *Nexus) skopeoAuthFile(t Target) (string, func(), error) {
	if n.cfg.Username == "" && n.cfg.Password == "" && n.cfg.Token == "" {
		return "", func() {}, nil
	}
	if n.cfg.Username == "" {
		return "", func() {}, errors.New(
			"для публикации Docker в Nexus задан ARTIFACT_TOKEN, но не задан ARTIFACT_USER")
	}
	prefix, _, err := n.nexusDockerPrefix(t, false)
	if err != nil {
		return "", func() {}, err
	}
	registryHost := strings.SplitN(prefix, "/", 2)[0]
	password := n.cfg.Password
	if password == "" {
		password = n.cfg.Token
	}
	payload, err := json.Marshal(map[string]any{
		"auths": map[string]any{
			registryHost: map[string]string{
				"auth": base64.StdEncoding.EncodeToString([]byte(n.cfg.Username + ":" + password)),
			},
		},
	})
	if err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp("", "moderation-skopeo-auth-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("временный auth-файл skopeo: %w", err)
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("запись auth-файла skopeo: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return name, cleanup, nil
}

func (n *Nexus) runSkopeo(ctx context.Context, t Target, args ...string) ([]byte, error) {
	authFile, cleanup, err := n.skopeoAuthFile(t)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, n.cfg.SkopeoBinary, args...)
	cmd.Env = os.Environ()
	if authFile != "" {
		cmd.Env = append(cmd.Env, "REGISTRY_AUTH_FILE="+authFile)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if len(message) > 1000 {
			message = message[:1000] + "…"
		}
		return out, fmt.Errorf("skopeo %s: %w: %s", args[0], err, message)
	}
	return out, nil
}

func writeOCIArchive(payload []byte) (string, func(), error) {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return "", func() {}, fmt.Errorf("OCI layout не является tar.gz: %w", err)
	}
	defer gz.Close()
	dir, err := os.MkdirTemp("", "moderation-oci-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("временный каталог OCI: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	name := filepath.Join(dir, "image.oci.tar")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if _, err := io.Copy(f, gz); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("распаковка OCI archive для skopeo: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return name, cleanup, nil
}

// PublishOCI переносит в hosted Docker repository Nexus исходный index и все
// его платформы. --preserve-digests запрещает skopeo перекодировать manifests:
// опубликованный index digest обязан совпасть с указанным в заявке.
func (n *Nexus) PublishOCI(ctx context.Context, t Target, layoutTarGz []byte) (string, error) {
	if n.cfg.DryRun {
		return "", errors.New("OCI-публикация вызвана в режиме dry-run: это ошибка вызывающего кода")
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
	source, cleanup, err := writeOCIArchive(layoutTarGz)
	if err != nil {
		return "", err
	}
	defer cleanup()
	destination, insecure, err := n.nexusTransportReference(t, false)
	if err != nil {
		return "", err
	}
	args := []string{"copy", "--all", "--preserve-digests", "--retry-times", "3"}
	if insecure {
		args = append(args, "--dest-tls-verify=false")
	}
	args = append(args, "oci-archive:"+source, destination)
	if _, err := n.runSkopeo(ctx, t, args...); err != nil {
		return "", fmt.Errorf("публикация multi-platform образа в Nexus: %w", err)
	}
	return n.nexusOCIReference(t), nil
}

func (n *Nexus) nexusOCIExists(ctx context.Context, t Target) (bool, error) {
	ref, insecure, err := n.nexusTransportReference(t, true)
	if err != nil {
		return false, err
	}
	args := []string{"inspect", "--raw"}
	if insecure {
		args = append(args, "--tls-verify=false")
	}
	args = append(args, ref)
	out, err := n.runSkopeo(ctx, t, args...)
	if err == nil {
		return true, nil
	}
	message := strings.ToLower(string(out) + " " + err.Error())
	for _, marker := range []string{"manifest unknown", "name unknown", "not found", "status code 404"} {
		if strings.Contains(message, marker) {
			return false, nil
		}
	}
	return false, err
}

func (n *Nexus) deleteOCI(ctx context.Context, t Target) (bool, error) {
	exists, err := n.nexusOCIExists(ctx, t)
	if err != nil || !exists {
		return false, err
	}
	ref, insecure, err := n.nexusTransportReference(t, true)
	if err != nil {
		return false, err
	}
	args := []string{"delete"}
	if insecure {
		args = append(args, "--tls-verify=false")
	}
	args = append(args, ref)
	if _, err := n.runSkopeo(ctx, t, args...); err != nil {
		return false, fmt.Errorf("удаление Docker-образа из Nexus: %w", err)
	}
	return true, nil
}

var _ OCIPublisher = (*Nexus)(nil)
