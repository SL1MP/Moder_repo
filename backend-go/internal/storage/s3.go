package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3Config — параметры подключения к S3-совместимому хранилищу.
type S3Config struct {
	Endpoint  string // http://minio:9000 — внутренний адрес, без прокси
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string // по умолчанию us-east-1: MinIO/SeaweedFS его игнорируют, но подпись без региона не считается
	// VirtualHost — адресация вида bucket.endpoint/key вместо endpoint/bucket/key.
	// Нулевое значение (false) даёт path-style: именно она нужна MinIO и
	// SeaweedFS, то есть тем хранилищам, с которыми сервис работает. Флаг
	// назван «от исключения» намеренно — флаг вида PathStyle с нулевым
	// значением false молча ломал бы адресацию у всех, кто не выставил его
	// явно, а комментарий «по умолчанию включена» этому противоречил бы.
	VirtualHost bool
	HTTPClient  *http.Client
}

// S3 — S3-совместимое хранилище с подписью AWS SigV4.
type S3 struct {
	cfg    S3Config
	client *http.Client
	// Now подменяется в тестах подписи.
	Now func() time.Time
}

func NewS3(cfg S3Config) (*S3, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, fmt.Errorf("S3_ENDPOINT не задан")
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, fmt.Errorf("S3_BUCKET не задан")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if !strings.Contains(cfg.Endpoint, "://") {
		cfg.Endpoint = "http://" + cfg.Endpoint
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &S3{cfg: cfg, client: client}, nil
}

func (s *S3) Bucket() string { return s.cfg.Bucket }

func (s *S3) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// objectURL собирает адрес объекта. Ключ экранируется посегментно: имя файла
// пакета может содержать «+» и «~» (обычное дело для версий nuget и go), а
// url.QueryEscape превратил бы «+» в пробел и объект перестал бы находиться.
func (s *S3) objectURL(key string) string {
	escaped := escapeKey(key)
	if s.cfg.VirtualHost {
		scheme, host, _ := strings.Cut(s.cfg.Endpoint, "://")
		return fmt.Sprintf("%s://%s.%s/%s", scheme, s.cfg.Bucket, host, escaped)
	}
	return fmt.Sprintf("%s/%s/%s", s.cfg.Endpoint, s.cfg.Bucket, escaped)
}

func (s *S3) bucketURL() string {
	if s.cfg.VirtualHost {
		scheme, host, _ := strings.Cut(s.cfg.Endpoint, "://")
		return fmt.Sprintf("%s://%s.%s", scheme, s.cfg.Bucket, host)
	}
	return fmt.Sprintf("%s/%s", s.cfg.Endpoint, s.cfg.Bucket)
}

// escapeKey экранирует ключ по правилам S3: каждый сегмент пути отдельно,
// разделители «/» остаются.
func escapeKey(key string) string {
	parts := strings.Split(strings.TrimPrefix(key, "/"), "/")
	for i, part := range parts {
		parts[i] = uriEncode(part, false)
	}
	return strings.Join(parts, "/")
}

// uriEncode — правило кодирования из спецификации SigV4: не кодируются
// A-Z a-z 0-9 - _ . ~ ; всё остальное — %XX в верхнем регистре. Именно этим
// оно отличается от url.QueryEscape (тот кодирует пробел как «+»), и именно
// на этом отличии подпись расходится с серверной.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/':
			if encodeSlash {
				b.WriteString("%2F")
			} else {
				b.WriteByte('/')
			}
		default:
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

// signingKey — производный ключ подписи SigV4: четыре последовательных HMAC от
// секрета через дату, регион и сервис. Вынесен отдельно, чтобы сверяться с
// документированным примером AWS: ошибка в порядке этих четырёх шагов даёт
// подпись, которую хранилище отвергает без внятного объяснения.
func signingKey(secret, dateStamp, region, service string) []byte {
	key := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	return hmacSHA256(key, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sign подписывает запрос по AWS Signature Version 4.
//
// Полностью по спецификации: канонический запрос -> строка для подписи ->
// производный ключ -> заголовок Authorization. Тело всегда подписывается
// целиком (payload hash), а не через UNSIGNED-PAYLOAD: артефакты помещаются
// в память и так, а подписанное тело защищает от подмены на пути до хранилища.
func (s *S3) sign(req *http.Request, payload []byte) {
	now := s.now()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(payload)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.Host != "" {
		req.Header.Set("Host", req.Host)
	} else {
		req.Header.Set("Host", req.URL.Host)
	}

	// Канонические заголовки: имена в нижнем регистре, отсортированы,
	// значения со схлопнутыми пробелами.
	var names []string
	values := map[string]string{}
	for name, vals := range req.Header {
		lower := strings.ToLower(name)
		// Подписываем только то, что заведомо дойдёт до сервера без правок
		// прокси: host, всё x-amz-*, content-type.
		if lower != "host" && lower != "content-type" && !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		names = append(names, lower)
		values[lower] = strings.Join(trimAll(vals), ",")
	}
	if _, ok := values["host"]; !ok {
		names = append(names, "host")
		values["host"] = req.URL.Host
	}
	sort.Strings(names)

	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + values[name] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := canonicalQueryString(req.URL.Query())

	canonicalRequest := strings.Join([]string{
		req.Method, canonicalURI, canonicalQuery,
		canonicalHeaders.String(), signedHeaders, payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, s.cfg.Region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	key := signingKey(s.cfg.SecretKey, dateStamp, s.cfg.Region, "s3")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.cfg.AccessKey, scope, signedHeaders, signature))
}

func trimAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.Join(strings.Fields(v), " ")
	}
	return out
}

func canonicalQueryString(query url.Values) string {
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), query[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// do выполняет подписанный запрос.
func (s *S3) do(ctx context.Context, method, rawURL string, payload []byte, headers map[string]string) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("сборка запроса к хранилищу: %w", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if payload != nil {
		req.ContentLength = int64(len(payload))
	}
	s.sign(req, payload)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("запрос к хранилищу: %w", err)
	}
	return resp, nil
}

// errorFromResponse превращает ответ в ошибку, сохраняя тело: сообщение S3 —
// единственное, что объясняет отказ (например, «bucket does not exist» против
// «signature does not match»), и терять его нельзя.
func errorFromResponse(resp *http.Response, action string) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w (%s)", ErrNotFound, action)
	}
	detail := strings.TrimSpace(string(body))
	if detail == "" {
		detail = resp.Status
	}
	return fmt.Errorf("хранилище отклонило %s: %d %s", action, resp.StatusCode, detail)
}

func (s *S3) EnsureBucket(ctx context.Context) error {
	resp, err := s.do(ctx, http.MethodHead, s.bucketURL(), nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("проверка бакета %s: %d %s", s.cfg.Bucket, resp.StatusCode, resp.Status)
	}

	create, err := s.do(ctx, http.MethodPut, s.bucketURL(), []byte{}, nil)
	if err != nil {
		return err
	}
	defer create.Body.Close()
	// 409 — бакет уже создан кем-то параллельно; это успех, а не ошибка.
	if create.StatusCode >= 400 && create.StatusCode != http.StatusConflict {
		return errorFromResponse(create, "создание бакета "+s.cfg.Bucket)
	}
	return nil
}

func (s *S3) Put(ctx context.Context, key string, data []byte, contentType string) (Object, error) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	resp, err := s.do(ctx, http.MethodPut, s.objectURL(key), data,
		map[string]string{"Content-Type": contentType})
	if err != nil {
		return Object{}, err
	}
	if resp.StatusCode >= 400 {
		return Object{}, errorFromResponse(resp, "запись объекта "+key)
	}
	resp.Body.Close()
	return Object{
		Bucket: s.cfg.Bucket, Key: key, SizeBytes: int64(len(data)),
		ContentType: contentType, LastModified: s.now(),
	}, nil
}

func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet, s.objectURL(key), nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, errorFromResponse(resp, "чтение объекта "+key)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("чтение тела объекта %s: %w", key, err)
	}
	return data, nil
}

func (s *S3) Stat(ctx context.Context, key string) (Object, error) {
	resp, err := s.do(ctx, http.MethodHead, s.objectURL(key), nil, nil)
	if err != nil {
		return Object{}, err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusNotFound {
			return Object{}, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return Object{}, fmt.Errorf("HEAD объекта %s: %d %s", key, resp.StatusCode, resp.Status)
	}
	obj := Object{Bucket: s.cfg.Bucket, Key: key, ContentType: resp.Header.Get("Content-Type")}
	if n := resp.ContentLength; n >= 0 {
		obj.SizeBytes = n
	}
	if modified, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		obj.LastModified = modified
	}
	return obj, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, http.MethodDelete, s.objectURL(key), nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 404 — объекта уже нет, это успех: шаг публикации вызывает удаление и на
	// повторном прогоне.
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		return errorFromResponse(resp, "удаление объекта "+key)
	}
	return nil
}

// listResult — ответ ListObjectsV2.
type listResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
}

// List обходит все страницы: усечённый по умолчанию список молча терял бы
// объекты начиная с тысячного, и вычистка префикса оставляла бы хвост.
func (s *S3) List(ctx context.Context, prefix string) ([]Object, error) {
	var out []Object
	token := ""
	for {
		query := url.Values{"list-type": {"2"}}
		if prefix != "" {
			query.Set("prefix", prefix)
		}
		if token != "" {
			query.Set("continuation-token", token)
		}
		resp, err := s.do(ctx, http.MethodGet, s.bucketURL()+"/?"+canonicalQueryString(query), nil, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 400 {
			return nil, errorFromResponse(resp, "список объектов по префиксу "+prefix)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("чтение списка объектов: %w", err)
		}
		var parsed listResult
		if err := xml.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("разбор списка объектов: %w", err)
		}
		for _, entry := range parsed.Contents {
			out = append(out, Object{
				Bucket: s.cfg.Bucket, Key: entry.Key,
				SizeBytes: entry.Size, LastModified: entry.LastModified,
			})
		}
		if !parsed.IsTruncated || parsed.NextContinuationToken == "" {
			return out, nil
		}
		token = parsed.NextContinuationToken
	}
}
