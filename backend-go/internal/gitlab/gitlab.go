// Package gitlab — интеграция с GitLab, ТОЛЬКО ЧТЕНИЕ.
//
// Порт backend/app/services/gitlab.py. OAuth-приложение GitLab, подключение из
// профиля пользователя, чтение файла зависимостей из приватного проекта от его
// имени с указанием ветки, тега или коммита.
//
// Границы заданы жёстко и снаружи: scope read_api read_repository, и сервис
// ничего не коммитит и не открывает merge request'ов. Это не самоограничение
// из вежливости — доступ выдаёт разработчик своей учётной записью, и всё, что
// сервис сможет сделать её правами, он сделает от его имени.
//
// Токены хранятся зашифрованными (internal/crypto, формат Fernet) и наружу не
// возвращаются никогда: ни в ответе API, ни в журнале, ни в тексте ошибки.
package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"moderation/internal/crypto"
	"moderation/internal/domain"
)

// Scopes — права, которые запрашиваются у GitLab.
//
// read_repository — читать файлы, read_api — узнать имя пользователя, чтобы
// показать в профиле, чьё подключение используется. Ничего на запись.
const Scopes = "read_api read_repository"

// MaxFileBytes — предел размера читаемого файла. Файл зависимостей —
// килобайты; пять мегабайт с большим запасом, и это защита от того, что по
// указанному пути окажется не он.
const MaxFileBytes = 5 << 20

// ErrNotConfigured — интеграция не настроена.
var ErrNotConfigured = errors.New("интеграция с GitLab не настроена")

// ErrNotConnected — пользователь не подключил GitLab.
var ErrNotConnected = errors.New("GitLab не подключён")

// ErrReconnect — токен истёк и обновить его нечем. Отдельная ошибка: чинится
// действием пользователя, а не администратора.
var ErrReconnect = errors.New("подключите GitLab заново")

// Config — параметры интеграции.
type Config struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	// Fernet — ключ шифрования токенов. nil означает, что FERNET_KEY не задан:
	// подключать GitLab нельзя, потому что хранить токен будет негде.
	Fernet *crypto.Fernet
	HTTP   *http.Client
}

// Store — что сервису нужно от базы.
//
// Интерфейс, а не *repo.Repo: подключение проверяется без поднятого Postgres,
// и список того, что интеграция вообще пишет в базу, виден целиком — это три
// поля одной строки, и ничего больше.
type Store interface {
	SetGitlabTokens(ctx context.Context, userID int64, access, refresh *string,
		expiresAt *time.Time, username *string) error
}

// Service — интеграция.
type Service struct {
	Cfg   Config
	Store Store
	// Now подменяется в тестах.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Service) client() *http.Client {
	if s.Cfg.HTTP != nil {
		return s.Cfg.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s *Service) base() string { return strings.TrimRight(s.Cfg.BaseURL, "/") }

// Enabled — настроена ли интеграция.
func (s *Service) Enabled() bool {
	return s.Cfg.BaseURL != "" && s.Cfg.ClientID != "" && s.Cfg.ClientSecret != ""
}

// requireConfig — понятная ошибка вместо запроса в никуда.
func (s *Service) requireConfig() error {
	if !s.Enabled() {
		return fmt.Errorf(
			"%w: задайте GITLAB_URL, GITLAB_OAUTH_CLIENT_ID и GITLAB_OAUTH_CLIENT_SECRET",
			ErrNotConfigured)
	}
	if s.Cfg.Fernet == nil {
		// Подключить GitLab без ключа шифрования нельзя: токен пришлось бы
		// хранить открытым, а это доступ к чужим репозиториям в виде строки
		// в базе.
		return fmt.Errorf("%w: не задан FERNET_KEY, хранить токены негде", ErrNotConfigured)
	}
	return nil
}

// AuthorizeURL — ссылка для подключения и state к ней.
//
// state возвращается вызывающему, а не хранится здесь: его проверяет тот, кто
// начал обмен, и хранить его в сервисе значило бы завести состояние ради
// одного запроса.
func (s *Service) AuthorizeURL(state string) (string, error) {
	if err := s.requireConfig(); err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("client_id", s.Cfg.ClientID)
	params.Set("redirect_uri", s.Cfg.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", Scopes)
	params.Set("state", state)
	return s.base() + "/oauth/authorize?" + params.Encode(), nil
}

// tokenResponse — ответ GitLab на обмен кода и на обновление.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// ExchangeCode обменивает код на токены и сохраняет их зашифрованными.
func (s *Service) ExchangeCode(ctx context.Context, user *domain.User, code string) error {
	if err := s.requireConfig(); err != nil {
		return err
	}
	form := url.Values{}
	form.Set("client_id", s.Cfg.ClientID)
	form.Set("client_secret", s.Cfg.ClientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", s.Cfg.RedirectURI)

	payload, err := s.postToken(ctx, form)
	if err != nil {
		return err
	}
	if payload.AccessToken == "" {
		return fmt.Errorf("GitLab не вернул access_token")
	}

	// Имя пользователя — для профиля: по нему видно, чьё подключение
	// используется. Недоступность этого запроса не отменяет подключения:
	// токены уже получены, и терять их из-за косметики нельзя.
	username := s.fetchUsername(ctx, payload.AccessToken)
	return s.save(ctx, user, payload, username)
}

// Refresh обновляет истёкший токен.
func (s *Service) Refresh(ctx context.Context, user *domain.User) (string, error) {
	if err := s.requireConfig(); err != nil {
		return "", err
	}
	if user.GitlabRefreshTokenEnc == nil || *user.GitlabRefreshTokenEnc == "" {
		return "", fmt.Errorf("срок действия токена GitLab истёк — %w", ErrReconnect)
	}
	refresh, err := s.Cfg.Fernet.Decrypt(*user.GitlabRefreshTokenEnc)
	if err != nil {
		// Ключ сменили — прежние токены нечитаемы. Пользователю нужно
		// подключиться заново, и сказать надо именно это, а не «ошибка
		// расшифровки».
		return "", fmt.Errorf("сохранённый токен GitLab не прочитан — %w", ErrReconnect)
	}

	form := url.Values{}
	form.Set("client_id", s.Cfg.ClientID)
	form.Set("client_secret", s.Cfg.ClientSecret)
	form.Set("refresh_token", refresh)
	form.Set("grant_type", "refresh_token")
	form.Set("redirect_uri", s.Cfg.RedirectURI)

	payload, err := s.postToken(ctx, form)
	if err != nil {
		return "", fmt.Errorf("не удалось обновить токен GitLab — %w", ErrReconnect)
	}
	if payload.RefreshToken == "" {
		// GitLab не всегда присылает новый refresh — тогда остаётся прежний.
		payload.RefreshToken = refresh
	}
	username := ""
	if user.GitlabUsername != nil {
		username = *user.GitlabUsername
	}
	if err := s.save(ctx, user, payload, username); err != nil {
		return "", err
	}
	return payload.AccessToken, nil
}

// AccessToken — действующий токен пользователя, с обновлением при истечении.
func (s *Service) AccessToken(ctx context.Context, user *domain.User) (string, error) {
	if user.GitlabAccessTokenEnc == nil || *user.GitlabAccessTokenEnc == "" {
		return "", fmt.Errorf(
			"%w. Откройте профиль и выполните подключение (scope read_repository)",
			ErrNotConnected)
	}
	if user.GitlabTokenExpiresAt != nil && !user.GitlabTokenExpiresAt.After(s.now()) {
		return s.Refresh(ctx, user)
	}
	token, err := s.Cfg.Fernet.Decrypt(*user.GitlabAccessTokenEnc)
	if err != nil {
		return "", fmt.Errorf("сохранённый токен GitLab не прочитан — %w", ErrReconnect)
	}
	return token, nil
}

// Disconnect убирает подключение.
func (s *Service) Disconnect(ctx context.Context, user *domain.User) error {
	if err := s.Store.SetGitlabTokens(ctx, user.ID, nil, nil, nil, nil); err != nil {
		return err
	}
	user.GitlabAccessTokenEnc, user.GitlabRefreshTokenEnc = nil, nil
	user.GitlabTokenExpiresAt, user.GitlabUsername = nil, nil
	return nil
}

// File — прочитанный файл.
type File struct {
	Project      string
	Path         string
	Ref          string
	Content      []byte
	CommitID     string
	LastCommitID string
}

// ReadFile читает файл зависимостей от имени пользователя.
//
// Ничего не пишет в репозиторий — ни здесь, ни где-либо ещё в этом пакете.
func (s *Service) ReadFile(ctx context.Context, user *domain.User, project, path, ref string) (*File, error) {
	if err := s.requireConfig(); err != nil {
		return nil, err
	}
	token, err := s.AccessToken(ctx, user)
	if err != nil {
		return nil, err
	}
	if ref == "" {
		ref = "HEAD"
	}

	// Идентификатор проекта и путь кодируются ЦЕЛИКОМ, вместе со слешами:
	// GitLab ждёт их именно так («group%2Fproject», «src%2Frequirements.txt»),
	// и незакодированный слеш превращает адрес в другой маршрут API.
	endpoint := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=%s",
		s.base(), url.QueryEscape(project),
		url.QueryEscape(strings.TrimPrefix(path, "/")), url.QueryEscape(ref))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("запрос к GitLab: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, fmt.Errorf(
			"файл «%s» не найден в проекте %s (ref: %s) либо нет доступа", path, project, ref)
	case http.StatusForbidden:
		return nil, fmt.Errorf(
			"GitLab отказал в доступе: у пользователя нет прав read_repository на этот проект")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("GitLab не принял токен — %w", ErrReconnect)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GitLab ответил %d", resp.StatusCode)
	}

	content, err := readLimited(resp.Body, MaxFileBytes)
	if err != nil {
		return nil, err
	}
	return &File{
		Project: project, Path: path, Ref: ref, Content: content,
		CommitID:     resp.Header.Get("X-Gitlab-Commit-Id"),
		LastCommitID: resp.Header.Get("X-Gitlab-Last-Commit-Id"),
	}, nil
}

// --------------------------------------------------------------------------- внутреннее

func (s *Service) postToken(ctx context.Context, form url.Values) (tokenResponse, error) {
	var payload tokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.base()+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return payload, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client().Do(req)
	if err != nil {
		return payload, fmt.Errorf("запрос токена к GitLab: %w", err)
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, 1<<20)
	if err != nil {
		return payload, err
	}
	if resp.StatusCode >= 400 {
		// Тело ответа НЕ показываем: GitLab кладёт в него присланные
		// параметры, включая client_secret.
		return payload, fmt.Errorf("GitLab отклонил обмен кода на токен (%d)", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return payload, fmt.Errorf("ответ GitLab не разобран: %w", err)
	}
	return payload, nil
}

func (s *Service) fetchUsername(ctx context.Context, token string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base()+"/api/v4/user", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.client().Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ""
	}
	body, err := readLimited(resp.Body, 1<<20)
	if err != nil {
		return ""
	}
	var payload struct {
		Username string `json:"username"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	return payload.Username
}

// save шифрует токены и кладёт их в базу.
func (s *Service) save(ctx context.Context, user *domain.User, payload tokenResponse, username string) error {
	access, err := s.Cfg.Fernet.Encrypt(payload.AccessToken)
	if err != nil {
		return fmt.Errorf("шифрование токена GitLab: %w", err)
	}
	var refresh *string
	if payload.RefreshToken != "" {
		encrypted, err := s.Cfg.Fernet.Encrypt(payload.RefreshToken)
		if err != nil {
			return fmt.Errorf("шифрование refresh-токена GitLab: %w", err)
		}
		refresh = &encrypted
	}
	var expiresAt *time.Time
	if payload.ExpiresIn > 0 {
		at := s.now().Add(time.Duration(payload.ExpiresIn) * time.Second)
		expiresAt = &at
	}
	var name *string
	if username != "" {
		name = &username
	}

	if err := s.Store.SetGitlabTokens(ctx, user.ID, &access, refresh, expiresAt, name); err != nil {
		return err
	}
	// Обновляем и копию в памяти: вызывающий работает с ней дальше, и
	// разойтись с базой она не должна.
	user.GitlabAccessTokenEnc, user.GitlabRefreshTokenEnc = &access, refresh
	user.GitlabTokenExpiresAt, user.GitlabUsername = expiresAt, name
	return nil
}
