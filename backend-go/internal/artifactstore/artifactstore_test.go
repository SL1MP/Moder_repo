package artifactstore_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"moderation/internal/artifactstore"
)

func newStore(t *testing.T, cfg artifactstore.Config, handler http.HandlerFunc) *artifactstore.HTTP {
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

func TestPublishSendsChecksumAndToken(t *testing.T) {
	var gotAuth, gotChecksum string
	var gotBody []byte
	store := newStore(t, artifactstore.Config{AuthType: artifactstore.AuthToken, Token: "секрет"},
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			gotAuth = r.Header.Get("Authorization")
			gotChecksum = r.Header.Get("X-Checksum-Sha256")
			gotBody = make([]byte, r.ContentLength)
			_, _ = r.Body.Read(gotBody)
			w.WriteHeader(http.StatusCreated)
		})

	url, err := store.Publish(context.Background(), "pypi-internal", "six/1.16.0/six.whl", []byte("байты"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !strings.HasSuffix(url, "/pypi-internal/six/1.16.0/six.whl") {
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

// TestPublishSkipsExisting — одна и та же версия приходит из разных заявок, и
// второй PUT в лучшем случае лишний, а в худшем подменяет байты, по которым
// уже принято решение.
func TestPublishSkipsExisting(t *testing.T) {
	var puts int
	store := newStore(t, artifactstore.Config{}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			return
		}
		puts++
		w.WriteHeader(http.StatusCreated)
	})

	if _, err := store.Publish(context.Background(), "repo", "path/file.whl", []byte("x")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if puts != 0 {
		t.Errorf("выполнено PUT: %d — уже опубликованная версия перезаписана", puts)
	}
}

func TestPublishErrorKeepsBody(t *testing.T) {
	store := newStore(t, artifactstore.Config{}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Deploy denied: repository is moderated"))
	})
	_, err := store.Publish(context.Background(), "repo", "p/f.whl", []byte("x"))
	if err == nil {
		t.Fatal("ошибки нет")
	}
	// Ровно этот ответ отличает «прямой PUT запрещён» от «нет прав» — открытый
	// вопрос про боевой Artifactory (docs/ci-parity-gaps.md).
	if !strings.Contains(err.Error(), "repository is moderated") {
		t.Errorf("err = %v — ответ артефактори потерян", err)
	}
}

// TestDryRunPublishIsCallerError — в режиме dry-run публиковать нельзя, и
// молча «успешно ничего не сделать» тоже нельзя: это пометило бы пакет
// опубликованным. Шаг обязан проверить DryRun() сам.
func TestDryRunPublishIsCallerError(t *testing.T) {
	store := newStore(t, artifactstore.Config{DryRun: true}, func(w http.ResponseWriter, r *http.Request) {
		t.Error("в режиме dry-run выполнен запрос к артефактори")
	})
	if !store.DryRun() {
		t.Fatal("DryRun() = false")
	}
	if _, err := store.Publish(context.Background(), "repo", "p/f", []byte("x")); err == nil {
		t.Error("публикация в dry-run завершилась успехом — пакет был бы помечен опубликованным")
	}
}

func TestStatFileMissingIsNil(t *testing.T) {
	store := newStore(t, artifactstore.Config{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	file, err := store.StatFile(context.Background(), "repo", "нет/такого")
	if err != nil {
		t.Fatalf("StatFile: %v", err)
	}
	if file != nil {
		t.Errorf("StatFile = %+v, ожидался nil", file)
	}
	exists, err := store.Exists(context.Background(), "repo", "нет/такого")
	if err != nil || exists {
		t.Errorf("Exists = %v, %v", exists, err)
	}
}

func TestBasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	store := newStore(t,
		artifactstore.Config{AuthType: artifactstore.AuthBasic, Username: "svc", Password: "pw"},
		func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok = r.BasicAuth()
			w.WriteHeader(http.StatusNotFound)
		})
	if _, err := store.Exists(context.Background(), "repo", "p"); err != nil {
		t.Fatal(err)
	}
	if !ok || user != "svc" || pass != "pw" {
		t.Errorf("basic auth = %q/%q (ok=%v)", user, pass, ok)
	}
}

func TestNewRequiresBaseURL(t *testing.T) {
	if _, err := artifactstore.New(artifactstore.Config{}); err == nil {
		t.Error("пустой ARTIFACT_BASE_URL принят")
	}
}
