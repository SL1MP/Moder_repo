package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Doer — минимальный контракт HTTP-клиента: столько, сколько нужно плагинам, и
// ровно столько, чтобы тесты подставляли фейковый реестр без поднятия сервера.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// registryUserAgent отличает сервис от дефолтного Go-http-client. Некоторые
// публичные реестры (в первую очередь Maven Central) применяют к безымянным
// клиентам более жёсткий rate limit.
const registryUserAgent = "pt-license-fetcher/1.0"

// HTTPStatusError сохраняет код ответа, чтобы плагин с несколькими зеркалами
// мог перейти к следующему источнику, не разбирая текст ошибки.
type HTTPStatusError struct {
	StatusCode int
	URL        string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("реестр ответил %d (%s)", e.StatusCode, e.URL)
}

// maxRegistryResponseBytes — ответ реестра метаданных, крупнее которого мы не
// читаем. Метаданные npm по популярному пакету со всей историей версий легко
// переваливают за десяток мегабайт, и без ограничения один запрос способен
// занять память под весь пул воркеров.
const maxRegistryResponseBytes = 64 * 1024 * 1024

func doer(h Doer) Doer {
	if h != nil {
		return h
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// getJSON выполняет GET и разбирает JSON-ответ.
//
// notFound возвращается как ErrNotFound: шаг конвейера обязан отличать
// «такой версии нет» (ошибка пользователя) от «реестр недоступен» (повод
// повторить), и делать это по типу ошибки, а не по тексту.
func getJSON(ctx context.Context, h Doer, url, accept string, dst any) error {
	body, err := getBytes(ctx, h, url, accept)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("ответ реестра не разобран (%s): %w", url, err)
	}
	return nil
}

func getBytes(ctx context.Context, h Doer, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("сборка запроса к реестру: %w", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", registryUserAgent)
	resp, err := doer(h).Do(req)
	if err != nil {
		return nil, fmt.Errorf("запрос к реестру (%s): %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return nil, ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode, URL: url}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("чтение ответа реестра (%s): %w", url, err)
	}
	return body, nil
}

// parseTime разбирает время в форматах, которыми отвечают реестры. Возвращает
// nil, если распознать не удалось: неизвестная дата публикации — это «карантин
// пропущен с пометкой», а не «дата 0001-01-01», по которой карантин молча
// посчитается пройденным.
func parseTime(value string) *time.Time {
	if value == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999", // pypi upload_time_iso_8601 без зоны
		"2006-01-02T15:04:05",        // pypi upload_time
		"2006-01-02T15:04:05.999999Z07:00",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			utc := parsed.UTC()
			return &utc
		}
	}
	return nil
}
