package artifactstore

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // обязательная контрольная сумма протокола Conan v2
	"encoding/hex"
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

func (n *Nexus) ArtifactURL(t Target) string {
	if t.Manager == "docker" {
		return n.nexusOCIReference(t)
	}
	if t.Manager == "conan" {
		if fileURL, err := n.conanRecipeURL(t); err == nil {
			return fileURL
		}
	}
	return n.fileURL(t.Repo, n.assetPath(t))
}

func (n *Nexus) StatFile(ctx context.Context, repo, path string) (*RemoteFile, error) {
	return n.stat(ctx, n.fileURL(repo, path), path)
}

func (n *Nexus) ReadFile(ctx context.Context, repo, path string) ([]byte, error) {
	return n.read(ctx, n.fileURL(repo, path), path)
}

func (n *Nexus) Exists(ctx context.Context, t Target) (bool, error) {
	if t.Manager == "docker" {
		return n.nexusOCIExists(ctx, t)
	}
	if t.Manager == "conan" {
		return n.conanExists(ctx, t)
	}
	file, err := n.StatFile(ctx, t.Repo, n.assetPath(t))
	return file != nil, err
}

// Publish выгружает компонент. Уже опубликованная версия не перезаписывается:
// та же версия приходит из разных заявок, а подменять байты, по которым уже
// принято решение, нельзя.
func (n *Nexus) Publish(ctx context.Context, t Target, data []byte) (string, error) {
	if t.Manager == "conan" {
		return n.publishConanRecipe(ctx, t, data)
	}
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

// conanRecipeURL возвращает адрес recipe archive в нативном Conan v2 API.
// Components API Nexus не описывает формат загрузки Conan: такие репозитории
// наполняются тем же протоколом, которым пользуется команда `conan upload`.
func (n *Nexus) conanRecipeURL(t Target) (string, error) {
	revision, err := conanRevision(t.SourceURL)
	if err != nil {
		return "", err
	}
	return n.fileURL(t.Repo, fmt.Sprintf(
		"v2/conans/%s/%s/_/_/revisions/%s/files/conan_export.tgz",
		url.PathEscape(t.Name), url.PathEscape(t.Version), url.PathEscape(revision))), nil
}

// conanRevision достаёт неизменяемую ревизию рецепта из URL ConanCenter:
// .../revisions/{rrev}/files/conan_export.tgz.
func conanRevision(sourceURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(sourceURL))
	if err != nil || parsed.Path == "" {
		return "", fmt.Errorf("Conan recipe revision не определена: некорректный source URL %q", sourceURL)
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] != "revisions" || parts[i+2] != "files" {
			continue
		}
		revision, unescapeErr := url.PathUnescape(parts[i+1])
		if unescapeErr == nil && revision != "" && !strings.ContainsAny(revision, "/\\") {
			return revision, nil
		}
	}
	return "", fmt.Errorf("Conan recipe revision не найдена в source URL %q", sourceURL)
}

// publishConanRecipe загружает уже проверенный conan_export.tgz без запуска
// conanfile.py. Вызов conan export здесь был бы опасен: рецепт — чужой Python-
// код и может выполнить произвольные действия ещё до помещения в Nexus.
func (n *Nexus) publishConanRecipe(ctx context.Context, t Target, data []byte) (string, error) {
	fileURL, err := n.conanRecipeURL(t)
	if err != nil {
		return "", err
	}
	if n.cfg.DryRun {
		return "", fmt.Errorf("публикация вызвана в режиме dry-run: это ошибка вызывающего кода")
	}
	token, err := n.conanToken(ctx, t.Repo)
	if err != nil {
		return "", err
	}
	exists, err := n.conanExistsWithToken(ctx, fileURL, token)
	if err != nil {
		return "", err
	}
	if exists {
		return fileURL, nil
	}
	sum := sha1.Sum(data) //nolint:gosec // Conan v2 требует X-Checksum-Sha1
	headers := map[string]string{
		"Content-Type":    "application/gzip",
		"X-Checksum-Sha1": hex.EncodeToString(sum[:]),
	}
	resp, err := n.doConan(ctx, http.MethodPut, fileURL, data, headers, token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", rejected(n.Kind(), fileURL, resp.StatusCode, raw)
	}
	return fileURL, nil
}

func (n *Nexus) conanExists(ctx context.Context, t Target) (bool, error) {
	fileURL, err := n.conanRecipeURL(t)
	if err != nil {
		return false, err
	}
	token, err := n.conanToken(ctx, t.Repo)
	if err != nil {
		return false, err
	}
	return n.conanExistsWithToken(ctx, fileURL, token)
}

func (n *Nexus) conanExistsWithToken(ctx context.Context, fileURL, token string) (bool, error) {
	resp, err := n.doConan(ctx, http.MethodHead, fileURL, nil, nil, token)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("Nexus ответил %d на проверку Conan recipe %s",
			resp.StatusCode, fileURL)
	}
	return true, nil
}

// conanToken повторяет обязательный шаг аутентификации Conan-клиента. Nexus
// принимает Basic credentials на /users/authenticate и возвращает bearer-
// токен, которым подписывается загрузка recipe file.
func (n *Nexus) conanToken(ctx context.Context, repo string) (string, error) {
	if n.cfg.AuthType == AuthToken {
		if token := strings.TrimSpace(n.cfg.Token); token != "" {
			return token, nil
		}
	}
	authURL := n.fileURL(repo, "v2/users/authenticate")
	resp, err := n.do(ctx, http.MethodGet, authURL, nil, map[string]string{"Accept": "text/plain"})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 400 {
		return "", rejected(n.Kind(), authURL, resp.StatusCode, body)
	}
	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("Nexus вернул пустой токен Conan")
	}
	return token, nil
}

func (n *Nexus) doConan(
	ctx context.Context, method, requestURL string, body []byte, headers map[string]string, token string,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("сборка запроса Conan к Nexus: %w", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	req.ContentLength = int64(len(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("запрос Conan к Nexus (%s %s): %w", method, requestURL, err)
	}
	return resp, nil
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
	if t.Manager == "docker" {
		return n.deleteOCI(ctx, t)
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
