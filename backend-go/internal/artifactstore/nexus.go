package artifactstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"moderation/internal/registry"
)

// Nexus — Sonatype Nexus 3. Выгрузка идёт компонентным REST API, а не PUT'ом
// по адресу файла: на PUT Nexus отвечает 405, потому что раскладку внутри
// репозитория он считает своим делом и строит её сам по формату.
type Nexus struct{ transport }

func (*Nexus) Kind() string { return KindNexus }

func (n *Nexus) fileURL(repo, path string) string {
	return fmt.Sprintf("%s/repository/%s/%s", n.cfg.BaseURL, repo, strings.TrimPrefix(path, "/"))
}

// assetPath — где Nexus хранит файл. Раскладка своя на каждый формат, и
// совпадать с раскладкой Artifactory она не обязана: по этому адресу файл
// потом отдаётся клиентам (pip, npm, go).
func (n *Nexus) assetPath(t Target) string {
	switch t.Manager {
	case "pypi":
		return fmt.Sprintf("packages/%s/%s/%s", t.Name, t.Version, t.Filename)
	case "npm":
		return fmt.Sprintf("%s/-/%s", t.DisplayName, t.Filename)
	case "go":
		// Модули лежат в raw-репозитории по схеме GOPROXY.
		return fmt.Sprintf("%s/@v/%s", registry.EscapeModule(t.DisplayName), t.Filename)
	}
	return fmt.Sprintf("%s/%s/%s", t.Name, t.Version, t.Filename)
}

func (n *Nexus) ArtifactURL(t Target) string { return n.fileURL(t.Repo, n.assetPath(t)) }

func (n *Nexus) StatFile(ctx context.Context, repo, path string) (*RemoteFile, error) {
	return n.stat(ctx, n.fileURL(repo, path), path)
}

func (n *Nexus) ReadFile(ctx context.Context, repo, path string) ([]byte, error) {
	return n.read(ctx, n.fileURL(repo, path), path)
}

func (n *Nexus) Exists(ctx context.Context, t Target) (bool, error) {
	file, err := n.StatFile(ctx, t.Repo, n.assetPath(t))
	return file != nil, err
}

// Publish выгружает компонент. Уже опубликованная версия не перезаписывается:
// та же версия приходит из разных заявок, а подменять байты, по которым уже
// принято решение, нельзя.
func (n *Nexus) Publish(ctx context.Context, t Target, data []byte) (string, error) {
	fileURL := n.ArtifactURL(t)
	if n.cfg.DryRun {
		return "", fmt.Errorf("публикация вызвана в режиме dry-run: это ошибка вызывающего кода, " +
			"шаг publish обязан проверять DryRun() до вызова Publish")
	}

	exists, err := n.Exists(ctx, t)
	if err != nil {
		return "", err
	}
	if exists {
		return fileURL, nil
	}

	body, contentType, err := n.componentForm(t, data)
	if err != nil {
		return "", err
	}
	upload := fmt.Sprintf("%s/service/rest/v1/components?repository=%s",
		n.cfg.BaseURL, url.QueryEscape(t.Repo))
	resp, err := n.do(ctx, http.MethodPost, upload, body, map[string]string{"Content-Type": contentType})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusConflict {
		// Пакет мог опубликовать параллельный прогон — тогда это не ошибка.
		if exists, existsErr := n.Exists(ctx, t); existsErr == nil && exists {
			return fileURL, nil
		}
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", rejected(n.Kind(), n.assetPath(t), resp.StatusCode, raw)
	}
	return fileURL, nil
}

// componentForm собирает multipart под формат репозитория. Имя поля с файлом
// у каждого формата своё, и ошибиться в нём значит получить 400 «missing
// asset» вместо публикации.
func (n *Nexus) componentForm(t Target, data []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)

	writeFile := func(field string) error {
		part, err := form.CreateFormFile(field, t.Filename)
		if err != nil {
			return err
		}
		_, err = part.Write(data)
		return err
	}

	var err error
	switch t.Manager {
	case "pypi":
		err = writeFile("pypi.asset")
	case "npm":
		err = writeFile("npm.asset")
	case "nuget":
		err = writeFile("nuget.asset")
	case "go":
		// go-модули Nexus хранит в raw-репозитории: каталог задаём сами.
		if err = form.WriteField("raw.directory", registry.EscapeModule(t.DisplayName)+"/@v"); err == nil {
			if err = writeFile("raw.asset1"); err == nil {
				err = form.WriteField("raw.asset1.filename", t.Filename)
			}
		}
	default:
		return nil, "", fmt.Errorf("для менеджера «%s» не задан формат компонента Nexus", t.Manager)
	}
	if err != nil {
		return nil, "", fmt.Errorf("сборка multipart для Nexus: %w", err)
	}
	if err := form.Close(); err != nil {
		return nil, "", fmt.Errorf("сборка multipart для Nexus: %w", err)
	}
	return buf.Bytes(), form.FormDataContentType(), nil
}

// nexusSearch — ответ поиска компонентов.
type nexusSearch struct {
	Items []struct {
		ID string `json:"id"`
	} `json:"items"`
}

// Delete снимает пакет с публикации.
//
// Удаляется компонент целиком, а не файл: в Nexus у компонента бывает
// несколько ассетов (wheel и sdist у pypi), и удалить один файл значит
// оставить версию наполовину доступной — install найдёт её и возьмёт остаток.
func (n *Nexus) Delete(ctx context.Context, t Target) (bool, error) {
	if n.cfg.DryRun {
		return false, fmt.Errorf("удаление вызвано в режиме dry-run: это ошибка вызывающего кода")
	}
	search := fmt.Sprintf("%s/service/rest/v1/search?repository=%s&name=%s&version=%s",
		n.cfg.BaseURL, url.QueryEscape(t.Repo), url.QueryEscape(t.Name), url.QueryEscape(t.Version))
	resp, err := n.do(ctx, http.MethodGet, search, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return false, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("Nexus ответил %d на поиск компонента %s %s",
			resp.StatusCode, t.DisplayName, t.Version)
	}
	var found nexusSearch
	if err := json.Unmarshal(body, &found); err != nil {
		return false, fmt.Errorf("ответ поиска Nexus не разобран: %w", err)
	}

	removed := false
	for _, item := range found.Items {
		if item.ID == "" {
			continue
		}
		delResp, err := n.do(ctx, http.MethodDelete,
			fmt.Sprintf("%s/service/rest/v1/components/%s", n.cfg.BaseURL, url.PathEscape(item.ID)),
			nil, nil)
		if err != nil {
			return removed, err
		}
		status := delResp.StatusCode
		delResp.Body.Close()
		switch {
		case status == http.StatusNotFound:
			// Уже удалён — считаем исход достигнутым.
		case status >= 400:
			return removed, fmt.Errorf("Nexus отклонил удаление компонента %s (%d)", item.ID, status)
		default:
			removed = true
		}
	}
	return removed, nil
}
