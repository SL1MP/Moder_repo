package artifactstore

import (
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
	"time"
)

// Сырые операции с файлами внутри репозитория артефактори.
//
// Отличие от Publish/Delete выше: те публикуют ПАКЕТ — раскладку выбирает
// артефактори по формату репозитория, и у Nexus она своя. Здесь же файл
// кладётся по тому пути, который задал вызывающий, и ничего о пакетах не
// предполагается. Нужны для двух вещей, появившихся вместе с отказом от S3:
//
//	промежуточная зона — скачанный пакет лежит в temp-репозитории, пока идут
//	                     проверки, и переезжает в репозиторий своего менеджера
//	                     после того, как все они пройдены;
//	отчёты             — JSON и HTML прогона, живущие дольше самого артефакта.
//
// Оба репозитория обязаны быть типа raw (generic у Artifactory): в них кладутся
// файлы по произвольным путям, а не пакеты, и никакой индексации формата им не
// нужно. В raw-репозиторий PUT'ом пишут обе системы — те 405, из-за которых
// появилось разделение nexus/generic, относятся к репозиториям форматов
// (pypi, npm, nuget), а не к raw.

// WriteFile кладёт файл по сырому пути внутри репозитория.
func (g *Generic) WriteFile(ctx context.Context, repo, filePath string, data []byte, contentType string) error {
	return writeRaw(ctx, &g.transport, g.Kind(), g.fileURL(repo, filePath), filePath, data, contentType)
}

func (n *Nexus) WriteFile(ctx context.Context, repo, filePath string, data []byte, contentType string) error {
	return writeRaw(ctx, &n.transport, n.Kind(), n.fileURL(repo, filePath), filePath, data, contentType)
}

func writeRaw(ctx context.Context, t *transport, kind, url, filePath string, data []byte, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	digest := sha256.Sum256(data)
	// Контрольную сумму шлём обеим системам: Artifactory сверяет её у себя и
	// отклоняет порченые байты, Nexus заголовок просто игнорирует. Порча на
	// пути обнаруживается артефактори, а не через полгода при установке.
	resp, err := t.do(ctx, http.MethodPut, url, data, map[string]string{
		"X-Checksum-Sha256": hex.EncodeToString(digest[:]),
		"Content-Type":      contentType,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return rejected(kind, filePath, resp.StatusCode, body)
	}
	return nil
}

// DeleteFile удаляет файл по сырому пути. false без ошибки — файла не было;
// это штатный исход, а не проблема: убрать из промежуточной зоны могут пакет,
// который туда не доехал.
func (g *Generic) DeleteFile(ctx context.Context, repo, filePath string) (bool, error) {
	return deleteRaw(ctx, &g.transport, g.fileURL(repo, filePath), filePath)
}

func (n *Nexus) DeleteFile(ctx context.Context, repo, filePath string) (bool, error) {
	return deleteRaw(ctx, &n.transport, n.fileURL(repo, filePath), filePath)
}

func deleteRaw(ctx context.Context, t *transport, url, filePath string) (bool, error) {
	resp, err := t.do(ctx, http.MethodDelete, url, nil, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, fmt.Errorf("артефактори отклонил удаление %s (%d): %s",
			filePath, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return true, nil
}

// --------------------------------------------------------------------------- перенос

// ErrMoveUnsupported — артефактори не умеет переносить файл своими силами.
// Не ошибка выполнения: вызывающий обязан скачать файл и выгрузить его сам.
// Отдельное значение, а не nil-результат, чтобы «не умеет» нельзя было принять
// за «перенёс».
var ErrMoveUnsupported = fmt.Errorf("артефактори не поддерживает перенос файла на своей стороне")

// MoveFile переносит файл внутри артефактори, не прогоняя байты через сервис.
//
// Это и есть модель публикации CI-версии: пакет никогда не проходит через
// процесс как байты, его перекладывает сам Artifactory
// (`api/move/{repo}/{path}?to=/{repo}/{path}`). Для промежуточной зоны это
// важно вдвойне — образ Docker или jar с зависимостями незачем качать второй
// раз только ради того, чтобы положить рядом.
func (g *Generic) MoveFile(ctx context.Context, srcRepo, srcPath, dstRepo, dstPath string) error {
	if g.cfg.DryRun {
		return fmt.Errorf("перенос вызван в режиме dry-run: это ошибка вызывающего кода")
	}
	endpoint := fmt.Sprintf("%s/api/move/%s/%s?to=/%s/%s",
		g.cfg.BaseURL,
		strings.Trim(srcRepo, "/"), strings.TrimPrefix(srcPath, "/"),
		strings.Trim(dstRepo, "/"), strings.TrimPrefix(dstPath, "/"))
	resp, err := g.do(ctx, http.MethodPost, endpoint, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// 404 на api/move — это не «файла нет»: так отвечает и артефактори, у
	// которого такого API просто нет (не Artifactory, а что-то совместимое
	// только по PUT). Отличить одно от другого можно лишь проверкой самого
	// файла, и без этой проверки вызывающий получил бы «перенесли» там, где
	// ничего не переносили.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		if file, statErr := g.StatFile(ctx, srcRepo, srcPath); statErr == nil && file == nil {
			return fmt.Errorf("переносить нечего: в %s нет файла %s", srcRepo, srcPath)
		}
		return ErrMoveUnsupported
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("артефактори отклонил перенос %s → %s/%s (%d): %s",
			srcPath, dstRepo, dstPath, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// MoveFile у Nexus не реализуем: компонентный API переносить между
// репозиториями не умеет (есть «staging move» только в Pro-редакции, и
// полагаться на неё нельзя). Возвращаем ErrMoveUnsupported, а вызывающий
// скачивает файл и выгружает его обычным путём — это по-прежнему работает,
// просто дороже.
func (n *Nexus) MoveFile(_ context.Context, _, _, _, _ string) error {
	return ErrMoveUnsupported
}

// --------------------------------------------------------------------------- обход

// ListFiles перечисляет файлы под префиксом. Используется уборкой
// промежуточной зоны: объект, о котором забыла база, обязан находиться и без
// неё, иначе зона растёт молча.
func (g *Generic) ListFiles(ctx context.Context, repo, prefix string) ([]RemoteFile, error) {
	endpoint := fmt.Sprintf("%s/api/storage/%s/%s?list&deep=1&listFolders=0",
		g.cfg.BaseURL, strings.Trim(repo, "/"), strings.Trim(prefix, "/"))
	resp, err := g.do(ctx, http.MethodGet, endpoint, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Пустого префикса нет как объекта — это не ошибка, это «ничего нет».
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("артефактори ответил %d на обход %s/%s: %s",
			resp.StatusCode, repo, prefix, strings.TrimSpace(string(body)))
	}

	var listing struct {
		Files []struct {
			URI          string `json:"uri"`
			Size         int64  `json:"size"`
			SHA256       string `json:"sha256"`
			LastModified string `json:"lastModified"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		return nil, fmt.Errorf("ответ обхода артефактори не разобран: %w", err)
	}
	out := make([]RemoteFile, 0, len(listing.Files))
	for _, f := range listing.Files {
		file := RemoteFile{
			Path:      path.Join(strings.Trim(prefix, "/"), strings.TrimPrefix(f.URI, "/")),
			SizeBytes: f.Size,
			Checksum:  f.SHA256,
		}
		if ts, err := time.Parse(time.RFC3339, f.LastModified); err == nil {
			file.LastModified = ts
		}
		out = append(out, file)
	}
	return out, nil
}

// ListFiles у Nexus — через поиск ассетов: обхода по пути компонентный API не
// предлагает.
func (n *Nexus) ListFiles(ctx context.Context, repo, prefix string) ([]RemoteFile, error) {
	var out []RemoteFile
	token := ""
	for {
		query := url.Values{}
		query.Set("repository", repo)
		if p := strings.Trim(prefix, "/"); p != "" {
			// Nexus сравнивает путь ассета по шаблону с *; префикс без него
			// нашёл бы только точное совпадение, то есть ничего.
			query.Set("q", p+"*")
		}
		if token != "" {
			query.Set("continuationToken", token)
		}
		endpoint := fmt.Sprintf("%s/service/rest/v1/search/assets?%s", n.cfg.BaseURL, query.Encode())
		resp, err := n.do(ctx, http.MethodGet, endpoint, nil, map[string]string{"Accept": "application/json"})
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("Nexus ответил %d на поиск ассетов в %s: %s",
				resp.StatusCode, repo, strings.TrimSpace(string(body)))
		}

		var page struct {
			Items []struct {
				Path     string `json:"path"`
				Checksum struct {
					SHA256 string `json:"sha256"`
				} `json:"checksum"`
				FileSize     int64  `json:"fileSize"`
				LastModified string `json:"lastModified"`
			} `json:"items"`
			ContinuationToken string `json:"continuationToken"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("ответ поиска ассетов Nexus не разобран: %w", err)
		}
		for _, item := range page.Items {
			file := RemoteFile{
				Path: strings.TrimPrefix(item.Path, "/"), SizeBytes: item.FileSize,
				Checksum: item.Checksum.SHA256,
			}
			if ts, err := time.Parse(time.RFC3339, item.LastModified); err == nil {
				file.LastModified = ts
			}
			out = append(out, file)
		}
		if page.ContinuationToken == "" {
			return out, nil
		}
		token = page.ContinuationToken
	}
}
