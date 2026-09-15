// Package artifactstore — публикация проверенного пакета во внутренний
// артефактори. Порт backend/app/adapters/artifact_store.py.
//
// Перенесена только generic-реализация (JFrog Artifactory и совместимые):
// production заказчика работает исключительно с Artifactory, Nexus не
// применяется нигде (docs/ci-parity-gaps.md). Переносить NexusArtifactStore до
// того, как выяснится, нужен ли он вообще, значило бы потратить фазу впустую.
//
// ОТКРЫТЫЙ ВОПРОС, влияющий на этот пакет: CI-версия публикует пакет
// server-side copy'ем внутри Artifactory (байты не проходят через процесс), а
// здесь реализовано скачивание с upstream и PUT. Разрешает ли боевой
// Artifactory прямой PUT в moderated-репозитории — не выяснено
// (docs/ci-parity-gaps.md). До выяснения DryRun=true — способ проверить
// доступ и креды без риска записи.
package artifactstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RemoteFile — метаданные файла в артефактори.
type RemoteFile struct {
	Path         string
	SizeBytes    int64
	Checksum     string
	LastModified time.Time
}

// Store — контракт артефактори.
type Store interface {
	// ArtifactURL — адрес, по которому пакет будет (или уже) опубликован.
	ArtifactURL(repo, path string) string
	// Exists — есть ли уже такой файл. Повторная публикация той же версии —
	// обычное дело (та же версия в двух заявках), и перезаписывать её нельзя.
	Exists(ctx context.Context, repo, path string) (bool, error)
	// Publish выгружает байты. Возвращает адрес опубликованного файла.
	Publish(ctx context.Context, repo, path string, data []byte) (string, error)
	// StatFile — метаданные файла; nil, если файла нет.
	StatFile(ctx context.Context, repo, path string) (*RemoteFile, error)
	// ReadFile — содержимое файла (нужно для снапшота OSV).
	ReadFile(ctx context.Context, repo, path string) ([]byte, error)
	// DryRun — включён ли режим «проверить доступ, но не писать».
	DryRun() bool
}

// AuthType — способ аутентификации в артефактори.
type AuthType string

const (
	AuthToken AuthType = "token" // Bearer — предпочтительно для Artifactory
	AuthBasic AuthType = "basic"
)

// Config — параметры артефактори.
type Config struct {
	BaseURL  string
	AuthType AuthType
	Token    string
	Username string
	Password string
	// DryRun — весь конвейер выполняется по-настоящему (реальное скачивание,
	// реальные сканеры), но в целевой артефактори реальные байты не пишутся.
	// Проверяется только достижимость и авторизация.
	DryRun     bool
	HTTPClient *http.Client
}

// HTTP — реализация поверх HTTP API артефактори.
type HTTP struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) (*HTTP, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("ARTIFACT_BASE_URL не задан")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.AuthType == "" {
		cfg.AuthType = AuthToken
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	return &HTTP{cfg: cfg, client: client}, nil
}

func (h *HTTP) DryRun() bool { return h.cfg.DryRun }

func (h *HTTP) ArtifactURL(repo, path string) string {
	return fmt.Sprintf("%s/%s/%s", h.cfg.BaseURL, repo, strings.TrimPrefix(path, "/"))
}

func (h *HTTP) authorize(req *http.Request) {
	switch h.cfg.AuthType {
	case AuthToken:
		if h.cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+h.cfg.Token)
		}
	case AuthBasic:
		if h.cfg.Username != "" {
			req.SetBasicAuth(h.cfg.Username, h.cfg.Password)
		}
	}
}

func (h *HTTP) do(ctx context.Context, method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("сборка запроса к артефактори: %w", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	h.authorize(req)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("запрос к артефактори (%s %s): %w", method, url, err)
	}
	return resp, nil
}

func (h *HTTP) StatFile(ctx context.Context, repo, path string) (*RemoteFile, error) {
	url := h.ArtifactURL(repo, path)
	resp, err := h.do(ctx, http.MethodHead, url, nil, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("артефактори ответил %d на HEAD %s", resp.StatusCode, path)
	}
	file := &RemoteFile{Path: path, Checksum: resp.Header.Get("X-Checksum-Sha256")}
	if resp.ContentLength >= 0 {
		file.SizeBytes = resp.ContentLength
	}
	if modified, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		file.LastModified = modified
	}
	return file, nil
}

func (h *HTTP) Exists(ctx context.Context, repo, path string) (bool, error) {
	file, err := h.StatFile(ctx, repo, path)
	return file != nil, err
}

func (h *HTTP) ReadFile(ctx context.Context, repo, path string) ([]byte, error) {
	resp, err := h.do(ctx, http.MethodGet, h.ArtifactURL(repo, path), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("артефактори ответил %d на чтение %s", resp.StatusCode, path)
	}
	return io.ReadAll(resp.Body)
}

// Publish выгружает пакет. Уже опубликованная версия не перезаписывается:
// одна и та же версия приходит из разных заявок, и второй PUT в лучшем случае
// лишний, а в худшем — подменяет байты, по которым уже принято решение.
func (h *HTTP) Publish(ctx context.Context, repo, path string, data []byte) (string, error) {
	url := h.ArtifactURL(repo, path)
	if h.cfg.DryRun {
		return "", fmt.Errorf("публикация вызвана в режиме dry-run: это ошибка вызывающего кода, " +
			"шаг publish обязан проверять DryRun() до вызова Publish")
	}

	exists, err := h.Exists(ctx, repo, path)
	if err != nil {
		return "", err
	}
	if exists {
		return url, nil
	}

	digest := sha256.Sum256(data)
	resp, err := h.do(ctx, http.MethodPut, url, data, map[string]string{
		// Artifactory сверяет контрольную сумму на своей стороне: так порча
		// байтов на пути обнаруживается им, а не через полгода при установке.
		"X-Checksum-Sha256": hex.EncodeToString(digest[:]),
		"Content-Type":      "application/octet-stream",
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("артефактори отклонил публикацию %s (%d): %s",
			path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return url, nil
}
