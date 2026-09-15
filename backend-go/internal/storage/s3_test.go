package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	testAccessKey = "AKIAIOSFODNN7EXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// TestSigningKeyMatchesAWSVector — сверка с документированным примером AWS
// («Examples of How to Derive a Signing Key»). Ошибка в порядке четырёх HMAC
// даёт подпись, которую хранилище отвергает без внятного объяснения, поэтому
// цепочка проверяется внешним эталоном, а не сама собой.
func TestSigningKeyMatchesAWSVector(t *testing.T) {
	got := hex.EncodeToString(signingKey(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam"))
	const want = "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
	if got != want {
		t.Errorf("производный ключ = %s, эталон AWS = %s", got, want)
	}
}

// TestURIEncodeFollowsSpec — правило кодирования SigV4 отличается от
// url.QueryEscape: пробел это %20, а не «+». Именно на этом отличии подпись
// расходится с серверной, а объект с «+» в имени (обычное дело для версий
// nuget и go) перестаёт находиться.
func TestURIEncodeFollowsSpec(t *testing.T) {
	cases := map[string]string{
		"обычный":         "%D0%BE%D0%B1%D1%8B%D1%87%D0%BD%D1%8B%D0%B9",
		"a b":             "a%20b",
		"a+b":             "a%2Bb",
		"tilde~dash-dot.": "tilde~dash-dot.",
		"under_score":     "under_score",
		"AZaz09":          "AZaz09",
		"%":               "%25",
	}
	for input, want := range cases {
		if got := uriEncode(input, true); got != want {
			t.Errorf("uriEncode(%q) = %q, ожидалось %q", input, got, want)
		}
	}
	if got := uriEncode("a/b", false); got != "a/b" {
		t.Errorf("разделитель пути не должен кодироваться в ключе: %q", got)
	}
	if got := uriEncode("a/b", true); got != "a%2Fb" {
		t.Errorf("в query разделитель обязан кодироваться: %q", got)
	}
}

func TestEscapeKeyKeepsSeparators(t *testing.T) {
	got := escapeKey("nuget/Newtonsoft.Json/13.0.1+build/Newtonsoft.Json.13.0.1.nupkg")
	want := "nuget/Newtonsoft.Json/13.0.1%2Bbuild/Newtonsoft.Json.13.0.1.nupkg"
	if got != want {
		t.Errorf("escapeKey = %q, ожидалось %q", got, want)
	}
}

func TestObjectURLAddressingStyles(t *testing.T) {
	// Нулевое значение VirtualHost — path-style, то есть то, что нужно MinIO.
	path, err := NewS3(S3Config{Endpoint: "http://minio:9000", Bucket: "art",
		AccessKey: testAccessKey, SecretKey: testSecretKey})
	if err != nil {
		t.Fatal(err)
	}
	if got := path.objectURL("pypi/six/1.16.0/six.whl"); got != "http://minio:9000/art/pypi/six/1.16.0/six.whl" {
		t.Errorf("path-style URL = %q", got)
	}

	virtual, err := NewS3(S3Config{Endpoint: "https://s3.example.com", Bucket: "art",
		VirtualHost: true, AccessKey: testAccessKey, SecretKey: testSecretKey})
	if err != nil {
		t.Fatal(err)
	}
	if got := virtual.objectURL("a/b.txt"); got != "https://art.s3.example.com/a/b.txt" {
		t.Errorf("virtual-host URL = %q", got)
	}
}

func TestEndpointWithoutSchemeGetsHTTP(t *testing.T) {
	s, err := NewS3(S3Config{Endpoint: "minio:9000", Bucket: "art"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.objectURL("k"), "http://minio:9000/") {
		t.Errorf("URL = %q, ожидалась схема по умолчанию", s.objectURL("k"))
	}
}

func TestNewS3RequiresEndpointAndBucket(t *testing.T) {
	if _, err := NewS3(S3Config{Bucket: "art"}); err == nil {
		t.Error("пустой endpoint принят")
	}
	if _, err := NewS3(S3Config{Endpoint: "http://minio:9000"}); err == nil {
		t.Error("пустой bucket принят")
	}
}

// --------------------------------------------------------------- проверка подписи

// verifySignature — независимая реализация проверки SigV4 по спецификации,
// написанная от сервера: пересобирает канонический запрос из того, что реально
// доехало, и сверяет подпись. Проверяет ровно то, что не проверить
// round-trip'ом — что подписано именно то, что отправлено.
func verifySignature(t *testing.T, r *http.Request, body []byte, region string) {
	t.Helper()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("нет заголовка Authorization: %q", auth)
	}
	var credential, signedHeaders, signature string
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch key {
		case "Credential":
			credential = value
		case "SignedHeaders":
			signedHeaders = value
		case "Signature":
			signature = value
		}
	}
	scopeParts := strings.SplitN(credential, "/", 2)
	if len(scopeParts) != 2 || scopeParts[0] != testAccessKey {
		t.Fatalf("Credential = %q", credential)
	}
	scope := scopeParts[1]
	dateStamp := strings.SplitN(scope, "/", 2)[0]

	// Канонические заголовки — строго из SignedHeaders, значениями из запроса.
	names := strings.Split(signedHeaders, ";")
	if !sort.StringsAreSorted(names) {
		t.Errorf("SignedHeaders не отсортированы: %q", signedHeaders)
	}
	var canonicalHeaders strings.Builder
	for _, name := range names {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}

	payloadHash := sha256Hex(body)
	if got := r.Header.Get("X-Amz-Content-Sha256"); got != payloadHash {
		t.Errorf("X-Amz-Content-Sha256 = %s, а тело даёт %s — подписано не то, что отправлено", got, payloadHash)
	}

	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	canonicalRequest := strings.Join([]string{
		r.Method, uri, canonicalQueryString(r.URL.Query()),
		canonicalHeaders.String(), signedHeaders, payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	mac := hmac.New(sha256.New, signingKey(testSecretKey, dateStamp, region, "s3"))
	mac.Write([]byte(stringToSign))
	if want := hex.EncodeToString(mac.Sum(nil)); want != signature {
		t.Errorf("подпись не сходится:\nполучено %s\nожидалось %s\nканонический запрос:\n%s",
			signature, want, canonicalRequest)
	}
}

// testServer — фейковое S3-хранилище, проверяющее подпись каждого запроса.
func testServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body []byte)) (*S3, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		verifySignature(t, r, body, "us-east-1")
		handler(w, r, body)
	}))
	t.Cleanup(srv.Close)

	s, err := NewS3(S3Config{
		Endpoint: srv.URL, Bucket: "artifacts",
		AccessKey: testAccessKey, SecretKey: testSecretKey,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, srv
}

func TestPutGetStatDeleteRoundTrip(t *testing.T) {
	objects := map[string][]byte{}
	contentTypes := map[string]string{}

	s, _ := testServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		key := strings.TrimPrefix(r.URL.Path, "/artifacts/")
		switch r.Method {
		case http.MethodPut:
			objects[key] = body
			contentTypes[key] = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			data, ok := objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", contentTypes[key])
			_, _ = w.Write(data)
		case http.MethodHead:
			data, ok := objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", contentTypes[key])
			w.Header().Set("Content-Length", fmt.Sprint(len(data)))
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			delete(objects, key)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	ctx := context.Background()
	key := ArtifactKey("nuget", "Newtonsoft.Json", "13.0.1+b", "Newtonsoft.Json.13.0.1.nupkg")
	payload := []byte("содержимое пакета")

	if _, err := s.Put(ctx, key, payload, "application/octet-stream"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("Get вернул %q", got)
	}
	info, err := s.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.SizeBytes != int64(len(payload)) {
		t.Errorf("Stat.SizeBytes = %d, ожидалось %d", info.SizeBytes, len(payload))
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, key); err == nil {
		t.Error("объект читается после удаления")
	}
}

// TestGetMissingIsErrNotFound — отличать «нет объекта» от «не смогли спросить»
// обязательно: на первом шаг перекачивает артефакт, на втором зовёт человека.
func TestGetMissingIsErrNotFound(t *testing.T) {
	s, _ := testServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := s.Get(context.Background(), "нет/такого")
	if err == nil {
		t.Fatal("ошибки нет")
	}
	if !strings.Contains(err.Error(), ErrNotFound.Error()) {
		t.Errorf("err = %v, ожидалась ErrNotFound", err)
	}
}

func TestServerErrorKeepsBody(t *testing.T) {
	s, _ := testServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<Error><Code>SignatureDoesNotMatch</Code></Error>"))
	})
	_, err := s.Put(context.Background(), "k", []byte("x"), "")
	if err == nil {
		t.Fatal("ошибки нет")
	}
	if !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("err = %v — сообщение хранилища потеряно, отказ не объяснить", err)
	}
}

func TestDeleteMissingIsNotError(t *testing.T) {
	s, _ := testServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := s.Delete(context.Background(), "нет/такого"); err != nil {
		t.Errorf("удаление отсутствующего объекта дало ошибку: %v", err)
	}
}

// TestListPaginates — усечённый список молча терял бы объекты начиная с
// тысячного, и вычистка префикса оставляла бы хвост.
func TestListPaginates(t *testing.T) {
	page := 0
	s, _ := testServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/xml")
		if page == 0 {
			page++
			if r.URL.Query().Get("prefix") != "reports/" {
				t.Errorf("prefix = %q", r.URL.Query().Get("prefix"))
			}
			_, _ = w.Write([]byte(`<ListBucketResult>
			  <IsTruncated>true</IsTruncated>
			  <NextContinuationToken>tok1</NextContinuationToken>
			  <Contents><Key>reports/1/sast_scan.json</Key><Size>10</Size></Contents>
			</ListBucketResult>`))
			return
		}
		if got := r.URL.Query().Get("continuation-token"); got != "tok1" {
			t.Errorf("continuation-token = %q, вторая страница запрошена неверно", got)
		}
		_, _ = w.Write([]byte(`<ListBucketResult>
		  <IsTruncated>false</IsTruncated>
		  <Contents><Key>reports/2/banner_scan.html</Key><Size>20</Size></Contents>
		</ListBucketResult>`))
	})

	objects, err := s.List(context.Background(), "reports/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objects) != 2 {
		t.Fatalf("объектов %d, ожидалось 2 (вторая страница не прочитана)", len(objects))
	}
	if objects[1].Key != "reports/2/banner_scan.html" {
		t.Errorf("objects[1].Key = %q", objects[1].Key)
	}
}

func TestEnsureBucketCreatesWhenMissing(t *testing.T) {
	var created bool
	s, _ := testServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut {
			created = true
			w.WriteHeader(http.StatusOK)
		}
	})
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	if !created {
		t.Error("бакет не создан")
	}
}

func TestEnsureBucketToleratesConflict(t *testing.T) {
	s, _ := testServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusConflict) // создан параллельно
	})
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Errorf("параллельное создание бакета трактовано как ошибка: %v", err)
	}
}

// --------------------------------------------------------------- ключи и типы

func TestArtifactAndReportKeys(t *testing.T) {
	if got := ArtifactKey("pypi", "six", "1.16.0", "six.whl"); got != "pypi/six/1.16.0/six.whl" {
		t.Errorf("ArtifactKey = %q", got)
	}
	// Отчёты живут под отдельным префиксом: артефакты вычищаются целыми
	// префиксами при отклонении пакета, отчёты обязаны это пережить.
	got := ReportKey(108, "sast_scan", "html")
	if got != "reports/108/sast_scan.html" {
		t.Errorf("ReportKey = %q", got)
	}
	if strings.HasPrefix(got, "pypi/") || !strings.HasPrefix(got, "reports/") {
		t.Error("отчёт лежит в префиксе артефактов — будет вычищен вместе с ними")
	}
}

func TestContentTypeFor(t *testing.T) {
	if got := ContentTypeFor("html"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("HTML-отчёт отдаётся как %q — браузер предложит скачать вместо показа", got)
	}
	if got := ContentTypeFor(".json"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("ContentTypeFor(json) = %q", got)
	}
	if got := ContentTypeFor("bin"); got != "application/octet-stream" {
		t.Errorf("ContentTypeFor(bin) = %q", got)
	}
}
