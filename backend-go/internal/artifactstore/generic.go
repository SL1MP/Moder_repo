package artifactstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Generic — JFrog Artifactory и совместимые: файл кладётся PUT'ом прямо по
// своему адресу.
type Generic struct{ transport }

func (*Generic) Kind() string { return KindGeneric }

func (g *Generic) fileURL(repo, path string) string {
	return fmt.Sprintf("%s/%s/%s", g.cfg.BaseURL, repo, strings.TrimPrefix(path, "/"))
}

func (g *Generic) ArtifactURL(t Target) string { return g.fileURL(t.Repo, t.Path) }

func (g *Generic) StatFile(ctx context.Context, repo, path string) (*RemoteFile, error) {
	return g.stat(ctx, g.fileURL(repo, path), path)
}

func (g *Generic) ReadFile(ctx context.Context, repo, path string) ([]byte, error) {
	return g.read(ctx, g.fileURL(repo, path), path)
}

func (g *Generic) Exists(ctx context.Context, t Target) (bool, error) {
	file, err := g.StatFile(ctx, t.Repo, t.Path)
	return file != nil, err
}

// Publish выгружает пакет. Уже опубликованная версия не перезаписывается:
// одна и та же версия приходит из разных заявок, и второй PUT в лучшем случае
// лишний, а в худшем — подменяет байты, по которым уже принято решение.
func (g *Generic) Publish(ctx context.Context, t Target, data []byte) (string, error) {
	url := g.ArtifactURL(t)
	if g.cfg.DryRun {
		return "", fmt.Errorf("публикация вызвана в режиме dry-run: это ошибка вызывающего кода, " +
			"шаг publish обязан проверять DryRun() до вызова Publish")
	}

	exists, err := g.Exists(ctx, t)
	if err != nil {
		return "", err
	}
	if exists {
		return url, nil
	}

	digest := sha256.Sum256(data)
	resp, err := g.do(ctx, http.MethodPut, url, data, map[string]string{
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
		return "", rejected(g.Kind(), t.Path, resp.StatusCode, body)
	}
	return url, nil
}
