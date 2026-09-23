package gitlab_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"moderation/internal/crypto"
	"moderation/internal/domain"
	"moderation/internal/gitlab"
)

// testKey — ключ Fernet для тестов. Настоящий формат, не заглушка: шифрование
// токенов здесь и есть предмет проверки.
const testKey = "GIRKJx3gWHW8cr_wQ1g9fzR7FQnBWKkS_d5q9-zlnRY="

// memStore — подставное хранилище подключения.
//
// Полное, а не «мок на один вызов»: сервис читает то, что сам записал (при
// обновлении токена), и хранилище, теряющее запись, скрыло бы это.
type memStore struct {
	access, refresh, username *string
	expiresAt                 *time.Time
	calls                     int
}

func (m *memStore) SetGitlabTokens(_ context.Context, _ int64,
	access, refresh *string, expiresAt *time.Time, username *string) error {
	m.calls++
	m.access, m.refresh, m.expiresAt, m.username = access, refresh, expiresAt, username
	return nil
}

func newService(t *testing.T, srv *httptest.Server, store *memStore) *gitlab.Service {
	t.Helper()
	fernet, err := crypto.New(testKey)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	base := ""
	if srv != nil {
		base = srv.URL
	}
	return &gitlab.Service{
		Cfg: gitlab.Config{
			BaseURL: base, ClientID: "cid", ClientSecret: "secret",
			RedirectURI: "https://moderation.test/gitlab/callback",
			Fernet:      fernet, HTTP: srv.Client(),
		},
		Store: store,
	}
}

// TestAuthorizeURLAsksReadOnlyScopes — сервис просит только чтение.
//
// Доступ выдаёт разработчик своей учётной записью, и всё, что сервис сможет
// сделать её правами, он сделает от его имени. Поэтому scope — предмет
// проверки, а не деталь.
func TestAuthorizeURLAsksReadOnlyScopes(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	s := newService(t, srv, &memStore{})

	url, err := s.AuthorizeURL("состояние-123")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	if !strings.Contains(url, "scope=read_api+read_repository") {
		t.Errorf("в ссылке не те права: %s", url)
	}
	for _, forbidden := range []string{"write_repository", "api&", "sudo"} {
		if strings.Contains(url, forbidden) {
			t.Errorf("в ссылке запрошено лишнее (%s): %s", forbidden, url)
		}
	}
	if !strings.Contains(url, "state=") {
		t.Errorf("в ссылке нет state: %s", url)
	}
}

// TestExchangeCodeStoresEncryptedTokens — токены ложатся в базу зашифрованными.
//
// Открытый токен в базе — это доступ к чужим репозиториям в виде строки,
// которую видно любому, кто читает базу.
func TestExchangeCodeStoresEncryptedTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "glpat-access", "refresh_token": "glpat-refresh",
				"expires_in": 7200,
			})
		case strings.HasSuffix(r.URL.Path, "/api/v4/user"):
			_ = json.NewEncoder(w).Encode(map[string]any{"username": "petrov"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := &memStore{}
	s := newService(t, srv, store)
	user := &domain.User{ID: 1}

	if err := s.ExchangeCode(context.Background(), user, "код-авторизации"); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if store.access == nil || store.refresh == nil {
		t.Fatal("токены не сохранены")
	}
	// В базе — шифртекст, а не токен.
	if strings.Contains(*store.access, "glpat-access") {
		t.Error("токен сохранён открытым")
	}
	if strings.Contains(*store.refresh, "glpat-refresh") {
		t.Error("refresh-токен сохранён открытым")
	}
	if store.username == nil || *store.username != "petrov" {
		t.Errorf("имя пользователя = %v", store.username)
	}
	if store.expiresAt == nil {
		t.Error("срок действия токена не сохранён — обновлять будет нечего")
	}

	// И читается обратно тем же сервисом.
	token, err := s.AccessToken(context.Background(), user)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "glpat-access" {
		t.Errorf("расшифрован %q", token)
	}
}

// TestExpiredTokenIsRefreshed — истёкший токен обновляется сам.
//
// Иначе подключение «слетает» через два часа, и пользователь обнаруживает это
// в момент, когда заводит заявку.
func TestExpiredTokenIsRefreshed(t *testing.T) {
	refreshed := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			refreshed++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "glpat-новый", "refresh_token": "glpat-новый-refresh",
				"expires_in": 7200,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := &memStore{}
	s := newService(t, srv, store)

	fernet, _ := crypto.New(testKey)
	oldAccess, _ := fernet.Encrypt("glpat-старый")
	oldRefresh, _ := fernet.Encrypt("glpat-старый-refresh")
	expired := time.Now().Add(-time.Hour)
	user := &domain.User{
		ID: 1, GitlabAccessTokenEnc: &oldAccess,
		GitlabRefreshTokenEnc: &oldRefresh, GitlabTokenExpiresAt: &expired,
	}

	token, err := s.AccessToken(context.Background(), user)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "glpat-новый" {
		t.Errorf("токен = %q, ожидался обновлённый", token)
	}
	if refreshed != 1 {
		t.Errorf("обращений за обновлением: %d", refreshed)
	}
	if store.calls == 0 {
		t.Error("обновлённый токен не сохранён — обновляться будет на каждом запросе")
	}
}

// TestRefreshWithoutRefreshTokenAsksToReconnect — обновлять нечем, и сказать
// надо именно это: чинится действием пользователя, а не администратора.
func TestRefreshWithoutRefreshTokenAsksToReconnect(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	s := newService(t, srv, &memStore{})

	fernet, _ := crypto.New(testKey)
	access, _ := fernet.Encrypt("glpat-старый")
	expired := time.Now().Add(-time.Hour)
	user := &domain.User{ID: 1, GitlabAccessTokenEnc: &access, GitlabTokenExpiresAt: &expired}

	_, err := s.AccessToken(context.Background(), user)
	if !errors.Is(err, gitlab.ErrReconnect) {
		t.Fatalf("ошибка = %v, ожидалось «подключите заново»", err)
	}
}

// TestNotConnectedIsItsOwnError — не подключено и не настроено это разные
// вещи: первое чинит пользователь, второе администратор.
func TestNotConnectedIsItsOwnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	s := newService(t, srv, &memStore{})

	_, err := s.AccessToken(context.Background(), &domain.User{ID: 1})
	if !errors.Is(err, gitlab.ErrNotConnected) {
		t.Errorf("ошибка = %v, ожидалось «не подключён»", err)
	}

	// Не настроено: адреса нет.
	empty := &gitlab.Service{Cfg: gitlab.Config{}, Store: &memStore{}}
	if _, err := empty.AuthorizeURL("x"); !errors.Is(err, gitlab.ErrNotConfigured) {
		t.Errorf("ошибка = %v, ожидалось «не настроено»", err)
	}
}

// TestReadFileEncodesProjectAndPath — идентификатор проекта и путь кодируются
// целиком, вместе со слешами.
//
// GitLab ждёт их именно так, и незакодированный слеш превращает адрес в
// другой маршрут API — запрос уходит в никуда и отвечает 404, который
// выглядит как «файла нет».
func TestReadFileEncodesProjectAndPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("X-Gitlab-Commit-Id", "abc123")
		_, _ = w.Write([]byte("requests==2.31.0\n"))
	}))
	defer srv.Close()

	s := newService(t, srv, &memStore{})
	fernet, _ := crypto.New(testKey)
	access, _ := fernet.Encrypt("glpat-access")
	user := &domain.User{ID: 1, GitlabAccessTokenEnc: &access}

	file, err := s.ReadFile(context.Background(), user,
		"группа/проект", "src/requirements.txt", "main")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(file.Content) != "requests==2.31.0\n" {
		t.Errorf("содержимое = %q", file.Content)
	}
	if file.CommitID != "abc123" {
		t.Errorf("коммит = %q — по нему заявку потом воспроизводят", file.CommitID)
	}
	// В пути не должно остаться неэкранированных слешей после /projects/.
	tail := gotPath[strings.Index(gotPath, "/projects/")+len("/projects/"):]
	segments := strings.Split(tail, "/")
	// projects/{id}/repository/files/{path}/raw — ровно пять сегментов.
	if len(segments) != 5 {
		t.Errorf("путь разбился на %d сегментов вместо 5: %s", len(segments), gotPath)
	}
}

// TestReadFileExplainsAccessDenied — 403 и 404 объясняются по-разному: в
// первом случае прав нет, во втором файла.
func TestReadFileExplainsAccessDenied(t *testing.T) {
	for status, want := range map[int]string{
		http.StatusForbidden: "read_repository",
		http.StatusNotFound:  "не найден",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		s := newService(t, srv, &memStore{})
		fernet, _ := crypto.New(testKey)
		access, _ := fernet.Encrypt("glpat-access")
		user := &domain.User{ID: 1, GitlabAccessTokenEnc: &access}

		_, err := s.ReadFile(context.Background(), user, "g/p", "req.txt", "main")
		if err == nil {
			t.Errorf("код %d принят как успех", status)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("код %d: ошибка %q не содержит %q", status, err.Error(), want)
		}
		srv.Close()
	}
}

// TestDisconnectClearsEverything — отключение убирает всё разом, а не по
// частям: «токен есть, срок нет» ничего не значит.
func TestDisconnectClearsEverything(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	store := &memStore{}
	s := newService(t, srv, store)

	access := "зашифровано"
	name := "petrov"
	expires := time.Now()
	user := &domain.User{
		ID: 1, GitlabAccessTokenEnc: &access, GitlabRefreshTokenEnc: &access,
		GitlabUsername: &name, GitlabTokenExpiresAt: &expires,
	}
	if err := s.Disconnect(context.Background(), user); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if store.access != nil || store.refresh != nil || store.username != nil || store.expiresAt != nil {
		t.Error("в базе осталась часть подключения")
	}
	if user.GitlabAccessTokenEnc != nil || user.GitlabUsername != nil {
		t.Error("копия в памяти разошлась с базой")
	}
}

// TestOversizedFileIsRejected — по указанному пути может оказаться не файл
// зависимостей. Молча прочитанный наполовину, он завёл бы заявку на часть
// пакетов — без единой ошибки.
func TestOversizedFileIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		big := strings.Repeat("x", gitlab.MaxFileBytes+10)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	s := newService(t, srv, &memStore{})
	fernet, _ := crypto.New(testKey)
	access, _ := fernet.Encrypt("glpat-access")
	user := &domain.User{ID: 1, GitlabAccessTokenEnc: &access}

	if _, err := s.ReadFile(context.Background(), user, "g/p", "big.txt", "main"); err == nil {
		t.Fatal("файл больше предела принят")
	}
}
