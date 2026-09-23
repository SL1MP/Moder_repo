package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/gitlab"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/requests"
)

// GitLab: подключение из профиля и заявка по файлу из приватного проекта.
//
// Порт backend/app/api/v1/gitlab.py. Только чтение: сервис ничего не коммитит
// и merge request'ов не открывает — см. комментарий к пакету internal/gitlab.

// GitlabHandler — зависимости маршрутов GitLab.
type GitlabHandler struct {
	Gitlab   *gitlab.Service
	Repo     *repo.Repo
	Registry *registry.Registry
	Cfg      *config.Config
	// Requests — обработчик заявок: заявка по файлу из GitLab создаётся тем же
	// кодом, что и любая другая. Своя копия создания разъехалась бы с общей
	// при первом же изменении.
	Requests *RequestsHandler
	Now      func() time.Time
}

func (h *GitlabHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

// MountGitlab подключает маршруты GitLab.
func MountGitlab(r chi.Router, h *GitlabHandler, a *Auth) {
	r.Route("/api/v1/gitlab", func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/status", h.Status)
		sub.Get("/authorize", h.Authorize)
		sub.Get("/callback", h.Callback)
		sub.Delete("/connection", h.Disconnect)
		if h.Requests != nil {
			sub.Post("/requests", h.CreateRequest)
		}
	})
}

// Status — GET /api/v1/gitlab/status
//
// Отвечает на два разных вопроса сразу: настроена ли интеграция вообще
// (это забота администратора) и подключил ли её этот пользователь (его
// собственная). Смешивать их нельзя: «не работает» по первой причине чинится
// в .env, по второй — кнопкой в профиле.
func (h *GitlabHandler) Status(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok || user == nil {
		writeError(w, r, errUnauthorized("Маршрут закрыт: пользователь не опознан"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":         h.Gitlab.Enabled(),
		"gitlab_url":      h.Cfg.GitlabURL,
		"connected":       user.GitlabAccessTokenEnc != nil && *user.GitlabAccessTokenEnc != "",
		"gitlab_username": user.GitlabUsername,
		"expires_at":      user.GitlabTokenExpiresAt,
		"scopes":          gitlab.Scopes,
	})
}

// Authorize — GET /api/v1/gitlab/authorize
func (h *GitlabHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	state, err := randomState()
	if err != nil {
		writeError(w, r, errInternal("Не удалось подготовить подключение").Because(err))
		return
	}
	url, err := h.Gitlab.AuthorizeURL(state)
	if err != nil {
		writeError(w, r, gitlabError(err))
		return
	}
	// state возвращается клиенту, а не хранится здесь: его проверяет тот, кто
	// начал обмен, и хранить его на сервере значило бы завести состояние ради
	// одного перехода.
	writeJSON(w, http.StatusOK, map[string]any{"authorize_url": url, "state": state})
}

// Callback — GET /api/v1/gitlab/callback?code=…
func (h *GitlabHandler) Callback(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok || user == nil {
		writeError(w, r, errUnauthorized("Маршрут закрыт: пользователь не опознан"))
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if len(code) < 8 {
		writeError(w, r, errValidation("Не передан код авторизации GitLab"))
		return
	}

	if err := h.Gitlab.ExchangeCode(r.Context(), user, code); err != nil {
		writeError(w, r, gitlabError(err))
		return
	}
	h.audit(r, user, "gitlab_connected", map[string]any{"gitlab_username": user.GitlabUsername})
	writeJSON(w, http.StatusOK, map[string]any{
		"connected": true, "gitlab_username": user.GitlabUsername,
	})
}

// Disconnect — DELETE /api/v1/gitlab/connection
func (h *GitlabHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok || user == nil {
		writeError(w, r, errUnauthorized("Маршрут закрыт: пользователь не опознан"))
		return
	}
	if err := h.Gitlab.Disconnect(r.Context(), user); err != nil {
		writeError(w, r, errInternal("Подключение не удалось убрать").Because(err))
		return
	}
	h.audit(r, user, "gitlab_disconnected", nil)
	writeJSON(w, http.StatusOK, map[string]any{"connected": false})
}

// gitlabRequestBody — тело запроса на заявку по файлу.
type gitlabRequestBody struct {
	Project string `json:"project"`
	Path    string `json:"path"`
	Ref     string `json:"ref"`
	// Manager необязателен: обычно определяется по имени файла.
	Manager           string `json:"manager"`
	Reason            string `json:"reason"`
	IncludeTransitive bool   `json:"include_transitive"`
	ResolveDepth      int    `json:"resolve_depth"`
}

// CreateRequest — POST /api/v1/gitlab/requests
//
// Заявка по файлу зависимостей из приватного проекта. Файл читается от имени
// пользователя его подключением — сервис своих прав в GitLab не имеет.
func (h *GitlabHandler) CreateRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok || user == nil {
		writeError(w, r, errUnauthorized("Маршрут закрыт: пользователь не опознан"))
		return
	}
	if len(user.Roles) == 0 {
		writeError(w, r, errForbidden(
			"У учётной записи нет ни одной роли сервиса. Проверьте членство в группах каталога "+
				"и переменные ROLE_MAPPING_*"))
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxDecisionBodyBytes))
	if err != nil {
		writeError(w, r, errValidation("Тело запроса не прочитано").Because(err))
		return
	}
	var body gitlabRequestBody
	if err := json.Unmarshal(raw, &body); err != nil {
		writeError(w, r, errValidation(
			"Ожидается JSON с полями project и path").Because(err))
		return
	}
	if strings.TrimSpace(body.Project) == "" || strings.TrimSpace(body.Path) == "" {
		writeError(w, r, errValidation(
			"Укажите project (группа/проект или его числовой id) и path (путь к файлу в нём)"))
		return
	}

	file, err := h.Gitlab.ReadFile(r.Context(), user, body.Project, body.Path, body.Ref)
	if err != nil {
		writeError(w, r, gitlabError(err))
		return
	}

	manager := body.Manager
	if manager == "" {
		manager = h.Registry.DetectByFile(body.Path)
	}
	if manager == "" {
		writeError(w, r, errValidation(
			"Не удалось определить пакетный менеджер по имени файла «"+body.Path+
				"» — укажите поле manager"))
		return
	}

	origin := "gitlab:" + body.Project + ":" + file.Ref + ":" + body.Path
	warning := "Файл прочитан из GitLab: " + origin
	if file.CommitID != "" {
		// Коммит — то, по чему заявку можно воспроизвести: ветка через месяц
		// указывает на другое содержимое.
		warning += " (commit " + file.CommitID + ")"
	}

	// Дальше — общий путь создания заявки: тот же разбор, то же раскрытие
	// зависимостей, тот же ответ. См. createFrom.
	h.Requests.createFrom(w, r, user, requests.Input{
		Manager:           manager,
		Filename:          body.Path,
		Content:           file.Content,
		Reason:            body.Reason,
		IncludeTransitive: body.IncludeTransitive,
		ResolveDepth:      body.ResolveDepth,
	}, []string{warning})
}

// audit пишет подключение и отключение в журнал.
//
// Токены в журнал не попадают — ни целиком, ни частями: журнал читают люди, а
// токен GitLab даёт доступ к чужим репозиториям.
func (h *GitlabHandler) audit(r *http.Request, user *domain.User, action string, value map[string]any) {
	if h.Repo == nil {
		return
	}
	entityID := strconv.FormatInt(user.ID, 10)
	entry := domain.AuditLog{
		ActorID: &user.ID, ActorName: user.Username,
		Action: action, EntityType: "user", EntityID: &entityID,
		Source: "ui", IP: ClientIP(r), CreatedAt: h.now(), NewValue: value,
	}
	if role := auth.PrimaryRole(user.Roles); role != "" {
		entry.ActorRole = &role
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
		defaultLogger.Printf("[%s] аудит подключения GitLab не записан: %v",
			RequestID(r.Context()), err)
	}
}

// gitlabError переводит ошибку интеграции в ответ API.
//
// Три разных случая, и путать их нельзя: «не настроено» чинит администратор,
// «не подключено» и «подключите заново» — сам пользователь кнопкой в профиле,
// а всё остальное — это ответ GitLab, и он уходит как есть.
func gitlabError(err error) *Error {
	switch {
	case errors.Is(err, gitlab.ErrNotConfigured):
		return &Error{Code: "not_configured", Status: http.StatusServiceUnavailable,
			Message: err.Error()}
	case errors.Is(err, gitlab.ErrNotConnected), errors.Is(err, gitlab.ErrReconnect):
		return errValidation(err.Error())
	}
	return errUpstream("GitLab: " + err.Error()).Because(err)
}

// randomState — одноразовое значение против подмены ответа OAuth.
func randomState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
