package artifactstore_test

import (
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"moderation/internal/artifactstore"
)

func newStore(t *testing.T, cfg artifactstore.Config, handler http.HandlerFunc) artifactstore.Store {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg.BaseURL = srv.URL
	cfg.HTTPClient = srv.Client()
	store, err := artifactstore.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

// pypiTarget — цель публикации обычного колеса.
func pypiTarget() artifactstore.Target {
	return artifactstore.Target{
		Repo: "pypi-internal", Manager: "pypi", Name: "six", DisplayName: "six",
		Version: "1.16.0", Filename: "six-1.16.0-py3-none-any.whl",
		Path: "six/1.16.0/six-1.16.0-py3-none-any.whl",
	}
}

// --------------------------------------------------------------- generic

func TestGenericPublishSendsChecksumAndToken(t *testing.T) {
	var gotAuth, gotChecksum, gotMethod string
	store := newStore(t, artifactstore.Config{
		Kind: artifactstore.KindGeneric, AuthType: artifactstore.AuthToken, Token: "секрет",
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotChecksum = r.Header.Get("X-Checksum-Sha256")
		w.WriteHeader(http.StatusCreated)
	})

	url, err := store.Publish(context.Background(), pypiTarget(), []byte("байты"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("метод = %q, у Artifactory это PUT", gotMethod)
	}
	if !strings.HasSuffix(url, "/pypi-internal/six/1.16.0/six-1.16.0-py3-none-any.whl") {
		t.Errorf("URL = %q", url)
	}
	if gotAuth != "Bearer секрет" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	// Artifactory сверяет сумму на своей стороне — так порча байтов на пути
	// обнаруживается им, а не через полгода при установке.
	if len(gotChecksum) != 64 {
		t.Errorf("X-Checksum-Sha256 = %q, ожидался sha256", gotChecksum)
	}
}

// Одна и та же версия приходит из разных заявок: второй PUT в лучшем случае
// лишний, а в худшем подменяет байты, по которым уже принято решение.
func TestGenericPublishSkipsExisting(t *testing.T) {
	published := false
	store := newStore(t, artifactstore.Config{Kind: artifactstore.KindGeneric},
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", "5")
				w.WriteHeader(http.StatusOK)
				return
			}
			published = true
			w.WriteHeader(http.StatusCreated)
		})

	if _, err := store.Publish(context.Background(), pypiTarget(), []byte("байты")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if published {
		t.Error("файл уже был в артефактори — выгрузки быть не должно")
	}
}

// --------------------------------------------------------------- nexus

// Nexus не принимает PUT по адресу файла: выгрузка идёт компонентным API,
// иначе в ответ прилетает 405 на каждом пакете.
func TestNexusPublishUsesComponentsAPI(t *testing.T) {
	var gotPath, gotQuery, gotMethod, gotField, gotFilename string
	var gotBody []byte
	store := newStore(t, artifactstore.Config{
		Kind: artifactstore.KindNexus, AuthType: artifactstore.AuthBasic,
		Username: "moderation", Password: "секрет",
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Errorf("Content-Type = %q: %v", r.Header.Get("Content-Type"), err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			gotField, gotFilename = part.FormName(), part.FileName()
			gotBody, _ = io.ReadAll(part)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	url, err := store.Publish(context.Background(), pypiTarget(), []byte("байты"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("метод = %q, компонентный API — это POST", gotMethod)
	}
	if gotPath != "/service/rest/v1/components" {
		t.Errorf("путь выгрузки = %q", gotPath)
	}
	if gotQuery != "repository=pypi-internal" {
		t.Errorf("параметры = %q", gotQuery)
	}
	if gotField != "pypi.asset" {
		t.Errorf("поле с файлом = %q, у формата pypi это pypi.asset", gotField)
	}
	if gotFilename != "six-1.16.0-py3-none-any.whl" || string(gotBody) != "байты" {
		t.Errorf("файл = %q (%q)", gotFilename, gotBody)
	}
	// Адрес файла у Nexus свой: /repository/ и раскладка формата.
	if !strings.HasSuffix(url, "/repository/pypi-internal/packages/six/1.16.0/six-1.16.0-py3-none-any.whl") {
		t.Errorf("URL = %q", url)
	}
}

// go-модули Nexus хранит в raw-репозитории: каталог задаём сами, иначе
// GOPROXY их не найдёт.
func TestNexusPublishGoModuleAsRaw(t *testing.T) {
	fields := map[string]string{}
	store := newStore(t, artifactstore.Config{Kind: artifactstore.KindNexus},
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			reader := multipart.NewReader(r.Body, params["boundary"])
			for {
				part, err := reader.NextPart()
				if err != nil {
					break
				}
				body, _ := io.ReadAll(part)
				if part.FileName() != "" {
					fields[part.FormName()] = "файл:" + part.FileName()
					continue
				}
				fields[part.FormName()] = string(body)
			}
			w.WriteHeader(http.StatusNoContent)
		})

	target := artifactstore.Target{
		Repo: "go-internal", Manager: "go",
		Name: "github.com/go-chi/chi/v5", DisplayName: "github.com/go-Chi/chi/v5",
		Version: "v5.0.10", Filename: "v5.0.10.zip", Path: "github.com/go-chi/chi/v5/@v/v5.0.10.zip",
	}
	if _, err := store.Publish(context.Background(), target, []byte("zip")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if fields["raw.directory"] != "github.com/go-!chi/chi/v5/@v" {
		t.Errorf("raw.directory = %q (заглавные буквы модуля экранируются)", fields["raw.directory"])
	}
	if fields["raw.asset1"] != "файл:v5.0.10.zip" {
		t.Errorf("raw.asset1 = %q", fields["raw.asset1"])
	}
	if fields["raw.asset1.filename"] != "v5.0.10.zip" {
		t.Errorf("raw.asset1.filename = %q", fields["raw.asset1.filename"])
	}
}

// Conan нельзя загружать через Components API: Nexus ожидает нативный Conan
// v2 protocol, иначе получившийся файл не виден команде `conan install`.
func TestNexusPublishConanRecipeThroughV2Protocol(t *testing.T) {
	const revision = "0123456789abcdef0123456789abcdef"
	var authenticated, uploaded bool
	store := newStore(t, artifactstore.Config{
		Kind: artifactstore.KindNexus, AuthType: artifactstore.AuthBasic,
		Username: "moderation", Password: "secret",
	}, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repository/conan-internal/v2/users/authenticate":
			user, password, ok := r.BasicAuth()
			if !ok || user != "moderation" || password != "secret" {
				t.Errorf("Basic auth = %q/%q, ok=%v", user, password, ok)
			}
			authenticated = true
			_, _ = w.Write([]byte("conan-jwt"))
		case strings.HasSuffix(r.URL.Path,
			"/v2/conans/boost/1.91.0/_/_/revisions/"+revision+"/files/conan_export.tgz"):
			if r.Header.Get("Authorization") != "Bearer conan-jwt" {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method != http.MethodPut {
				t.Errorf("метод = %s, ожидался PUT", r.Method)
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != "recipe-bytes" {
				t.Errorf("тело = %q", body)
			}
			if len(r.Header.Get("X-Checksum-Sha1")) != 40 {
				t.Errorf("X-Checksum-Sha1 = %q", r.Header.Get("X-Checksum-Sha1"))
			}
			uploaded = true
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("неожиданный запрос %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	target := artifactstore.Target{
		Repo: "conan-internal", Manager: "conan", Name: "boost", DisplayName: "boost",
		Version: "1.91.0", Filename: "boost-1.91.0-0123456789ab.tgz",
		SourceURL: "https://center2.conan.io/v2/conans/boost/1.91.0/_/_/revisions/" +
			revision + "/files/conan_export.tgz",
	}
	gotURL, err := store.Publish(context.Background(), target, []byte("recipe-bytes"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !authenticated || !uploaded {
		t.Fatalf("authenticated=%v uploaded=%v", authenticated, uploaded)
	}
	if !strings.Contains(gotURL, "/repository/conan-internal/v2/conans/boost/1.91.0/") {
		t.Errorf("URL = %q", gotURL)
	}
}

func TestNexusConanPublishRequiresRecipeRevision(t *testing.T) {
	store := newStore(t, artifactstore.Config{Kind: artifactstore.KindNexus},
		func(w http.ResponseWriter, _ *http.Request) {
			t.Error("без recipe revision сетевого запроса быть не должно")
			w.WriteHeader(http.StatusInternalServerError)
		})
	_, err := store.Publish(context.Background(), artifactstore.Target{
		Repo: "conan-internal", Manager: "conan", Name: "boost", Version: "1.91.0",
		SourceURL: "https://center2.conan.io/not-a-revision/conan_export.tgz",
	}, []byte("recipe"))
	if err == nil || !strings.Contains(err.Error(), "recipe revision") {
		t.Fatalf("ошибка = %v", err)
	}
}

// Параллельный прогон мог опубликовать ту же версию — это не ошибка.
func TestNexusPublishIsIdempotentOnConflict(t *testing.T) {
	uploads := 0
	store := newStore(t, artifactstore.Config{Kind: artifactstore.KindNexus},
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				// Первый HEAD — файла нет, после попытки выгрузки — уже есть.
				if uploads == 0 {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Length", "5")
				w.WriteHeader(http.StatusOK)
				return
			}
			uploads++
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("component already exists"))
		})

	url, err := store.Publish(context.Background(), pypiTarget(), []byte("байты"))
	if err != nil {
		t.Fatalf("публикация уже существующего компонента не должна быть ошибкой: %v", err)
	}
	if !strings.Contains(url, "/repository/pypi-internal/") {
		t.Errorf("URL = %q", url)
	}
}

// --------------------------------------------------------------- ошибки

// 405 — почти всегда не доступ, а неверный тип артефактори. Ответ обязан это
// назвать: иначе администратор стенда ищет проблему в правах.
func TestMethodNotAllowedNamesStoreKind(t *testing.T) {
	store := newStore(t, artifactstore.Config{Kind: artifactstore.KindGeneric},
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		})

	_, err := store.Publish(context.Background(), pypiTarget(), []byte("байты"))
	if err == nil {
		t.Fatal("405 обязан быть ошибкой")
	}
	text := err.Error()
	for _, want := range []string{"405", "ARTIFACT_STORE", "generic", "nexus", "hosted"} {
		if !strings.Contains(text, want) {
			t.Errorf("в сообщении нет %q: %s", want, text)
		}
	}
}

func TestForbiddenPointsAtCredentials(t *testing.T) {
	store := newStore(t, artifactstore.Config{Kind: artifactstore.KindNexus},
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})

	_, err := store.Publish(context.Background(), pypiTarget(), []byte("байты"))
	if err == nil || !strings.Contains(err.Error(), "ARTIFACT_TOKEN") {
		t.Fatalf("403 должен указывать на учётные данные: %v", err)
	}
}

// Опечатка в ARTIFACT_STORE не должна молча превращаться в «публикуем как в
// Artifactory»: на Nexus это 405 на каждом пакете.
func TestUnknownKindIsRejected(t *testing.T) {
	_, err := artifactstore.New(artifactstore.Config{Kind: "nexsus", BaseURL: "http://example"})
	if err == nil || !strings.Contains(err.Error(), "ARTIFACT_STORE") {
		t.Fatalf("ожидалась ошибка про ARTIFACT_STORE, получено %v", err)
	}
}

func TestDefaultKindIsNexus(t *testing.T) {
	store, err := artifactstore.New(artifactstore.Config{BaseURL: "http://example"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Значение по умолчанию совпадает с python-версией и .env.example.
	if store.Kind() != artifactstore.KindNexus {
		t.Errorf("по умолчанию = %q, ожидался nexus", store.Kind())
	}
}
