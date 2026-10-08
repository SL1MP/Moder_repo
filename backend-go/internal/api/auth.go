package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
)

// Маршруты доступа. Порт backend/app/api/v1/auth.py.
//
// Формат ответов совпадает с python-версией дословно: frontend/src/lib/auth.ts
// читает /auth/config на старте и решает по нему, куда вести пользователя.
// Любое расхождение здесь ломает вход, причём молча — SPA просто не найдёт
// поле и уедет в пустой экран.

// AuthHandler — зависимости маршрутов доступа.
type AuthHandler struct {
	Auth *Auth
	Cfg  *config.Config
}

// maxLoginBodyBytes — тело запроса на вход. Логин и пароль в килобайт
// укладываются с большим запасом, а читать неограниченный поток от
// неаутентифицированного клиента нельзя.
const maxLoginBodyBytes = 4 << 10

// MountAuth подключает маршруты доступа. config и token открыты (иначе
// войти невозможно), me закрыт проверкой токена.
func MountAuth(r chi.Router, h *AuthHandler) {
	r.Route("/api/v1/auth", func(sub chi.Router) {
		sub.Get("/config", h.Config)
		sub.Post("/token", h.LocalLogin)
		sub.Post("/refresh", h.Refresh)
		sub.Get("/oidc/login", h.OIDCLogin)
		sub.Get("/oidc/callback", h.OIDCCallback)
		sub.With(h.Auth.Authenticate).Get("/me", h.Me)
		sub.With(h.Auth.Authenticate).Post("/me/password", h.ChangePassword)
		sub.With(h.Auth.Authenticate).Get("/me/tokens", h.APITokens)
		sub.With(h.Auth.Authenticate).Post("/me/tokens", h.CreateAPIToken)
		sub.With(h.Auth.Authenticate).Delete("/me/tokens/{tokenID}", h.DeleteAPIToken)
	})
}

// Config — GET /api/v1/auth/config. Публичные параметры способов входа.
// Сам Authorization Code + PKCE выполняет backend: SPA получает только URL,
// с которого нужно начать серверный OIDC-flow.
func (h *AuthHandler) Config(w http.ResponseWriter, r *http.Request) {
	cfg := h.Cfg
	oidcEnabled, oidcLabel := false, "Keycloak (SSO)"
	oidcIssuer, oidcClientID := cfg.BrowserIssuer(), cfg.OIDCClientID
	if h.Auth.SessionRepo != nil {
		if current, err := h.Auth.SessionRepo.OIDCSettings(r.Context()); err == nil {
			oidcEnabled = current.Enabled && current.Issuer != "" && current.ClientID != ""
			oidcIssuer = current.Issuer
			oidcClientID = current.ClientID
			if current.ButtonLabel != "" {
				oidcLabel = current.ButtonLabel
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		// Издатель здесь ВНЕШНИЙ: по нему в Keycloak пойдёт браузер, а не
		// сервис. Подстановка внутреннего адреса — самая частая причина
		// «кнопка входа ведёт в никуда».
		"issuer":             oidcIssuer,
		"client_id":          oidcClientID,
		"scopes":             []string{"openid", "profile", "email"},
		"flow":               "authorization_code_pkce",
		"local_auth_enabled": cfg.LocalAuthEnabled,
		"oidc_enabled":       oidcEnabled,
		"oidc_button_label":  oidcLabel,
		"oidc_login_url":     "/api/v1/auth/oidc/login",
		"app_name":           cfg.AppName,
		"app_env":            cfg.AppEnv,
		"gitlab_enabled":     cfg.GitlabURL != "" && cfg.GitlabOAuthClientID != "",
		"role_mapping": map[string]string{
			"admin":     cfg.RoleMappingAdmin,
			"devsecops": cfg.RoleMappingDevSecOps,
			"legal":     cfg.RoleMappingLegal,
			"developer": cfg.RoleMappingDeveloper,
		},
	})
}

// Me — GET /api/v1/auth/me. Текущий пользователь и его роли.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут /auth/me не закрыт проверкой токена"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                   user.ID,
		"username":             user.Username,
		"display_name":         user.DisplayName(),
		"email":                user.Email,
		"roles":                rolesOrEmpty(user.Roles),
		"is_service":           user.IsService,
		"source":               user.Source,
		"is_superuser":         user.IsSuperuser,
		"must_change_password": user.MustChangePassword,
		// SPA использует этот признак, чтобы показать состояние подключения GitLab.
		"gitlab_connected": user.GitlabRefreshTokenEnc != nil || user.GitlabAccessTokenEnc != nil,
	})
}

// LocalLogin — POST /api/v1/auth/token. Вход локальных пользователей и
// сервисных учёток, включаемый флагом LOCAL_AUTH_ENABLED.
func (h *AuthHandler) LocalLogin(w http.ResponseWriter, r *http.Request) {
	if !h.Cfg.LocalAuthEnabled {
		writeError(w, r, errUnauthorized(
			"Локальная аутентификация отключена. Используйте вход через SSO (LOCAL_AUTH_ENABLED=false)"))
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLoginBodyBytes)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Ожидается JSON с полями username и password").Because(err))
		return
	}
	if payload.Username == "" || payload.Password == "" {
		writeError(w, r, errValidation("Логин и пароль обязательны"))
		return
	}

	ip := ""
	if value := ClientIP(r); value != nil {
		ip = *value
	}
	if h.Auth.SessionRepo != nil {
		if retry, err := h.Auth.SessionRepo.LoginBlock(r.Context(), payload.Username, ip); err != nil {
			writeError(w, r, errInternal("Не удалось проверить ограничение входа").Because(err))
			return
		} else if retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
			writeError(w, r, &Error{Code: "too_many_attempts", Status: http.StatusTooManyRequests,
				Message: "Слишком много неудачных попыток входа. Повторите позже."})
			return
		}
	}

	user, err := h.Auth.Repo.GetUserByUsername(r.Context(), payload.Username)
	if err != nil {
		writeError(w, r, errInternal("Не удалось проверить учётную запись").Because(err))
		return
	}

	// Ответ на неверный логин и на неверный пароль одинаков намеренно: иначе
	// по разнице ответов перебирается список существующих учёток.
	if user == nil || !user.IsActive || (user.Source != "" && user.Source != "local") || !auth.VerifyPassword(payload.Password, user.PasswordHash) {
		if h.Auth.SessionRepo != nil {
			_ = h.Auth.SessionRepo.RecordLoginFailure(r.Context(), payload.Username, ip)
		}
		h.recordLogin(r, "local_login_failed", nil, payload.Username, "denied")
		writeError(w, r, errUnauthorized("Неверный логин или пароль"))
		return
	}

	token, refresh, ttl, err := h.issuePair(r, user)
	if err != nil {
		writeError(w, r, errUnauthorized(err.Error()).Because(err))
		return
	}
	// Отметка о времени входа не повод отказать во входе: токен уже выпущен и
	// действителен, а не записанное время входа — это неполный журнал, а не
	// отказ в обслуживании.
	if err := h.Auth.Repo.TouchLastLogin(r.Context(), user.ID, h.Auth.now()); err != nil {
		defaultLogger.Printf("[%s] не удалось отметить вход %q: %v",
			RequestID(r.Context()), user.Username, err)
	}
	h.recordLogin(r, "local_login", user, user.Username, "ok")
	if h.Auth.SessionRepo != nil {
		_ = h.Auth.SessionRepo.ClearLoginFailures(r.Context(), payload.Username, ip)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  token,
		"refresh_token": refresh,
		"token_type":    "bearer",
		"expires_in":    ttl,
		"roles":         rolesOrEmpty(user.Roles),
	})
}

func (h *AuthHandler) issuePair(r *http.Request, user *domain.User) (string, string, int, error) {
	access, ttl, err := h.Auth.Verifier.IssueLocalToken(user)
	if err != nil {
		return "", "", 0, err
	}
	if h.Auth.SessionRepo == nil {
		return access, "", ttl, nil
	}
	refresh, hash, err := auth.NewOpaqueToken("")
	if err != nil {
		return "", "", 0, err
	}
	ttlRefresh := h.Auth.RefreshTTL
	if ttlRefresh <= 0 {
		ttlRefresh = 30 * 24 * time.Hour
	}
	if err := h.Auth.SessionRepo.StoreRefreshToken(r.Context(), user.ID, hash, h.Auth.now().Add(ttlRefresh)); err != nil {
		return "", "", 0, err
	}
	return access, refresh, ttl, nil
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if h.Auth.SessionRepo == nil {
		writeError(w, r, errUnauthorized("Refresh-сессии не настроены"))
		return
	}
	var payload struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLoginBodyBytes)).Decode(&payload); err != nil || payload.RefreshToken == "" {
		writeError(w, r, errValidation("refresh_token обязателен"))
		return
	}
	userID, err := h.Auth.SessionRepo.ConsumeRefreshToken(r.Context(), auth.HashToken(payload.RefreshToken))
	if err != nil || userID == 0 {
		writeError(w, r, errUnauthorized("Недействительный refresh token"))
		return
	}
	user, err := h.Auth.SessionRepo.GetUserByID(r.Context(), userID)
	if err != nil || user == nil || !user.IsActive {
		writeError(w, r, errUnauthorized("Пользователь сессии недоступен"))
		return
	}
	access, refresh, ttl, err := h.issuePair(r, user)
	if err != nil {
		writeError(w, r, errInternal("Сессия не обновлена").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": refresh,
		"token_type": "bearer", "expires_in": ttl})
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := CurrentUser(r.Context())
	if user == nil {
		writeError(w, r, errUnauthorized("Пользователь не определён"))
		return
	}
	if user.Source != "local" {
		writeError(w, r, errForbidden("Пароль управляется провайдером идентификации"))
		return
	}
	var payload struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLoginBodyBytes)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Данные смены пароля не разобраны"))
		return
	}
	if len([]rune(payload.New)) < 6 {
		writeError(w, r, errValidation("Новый пароль должен содержать не менее 6 символов"))
		return
	}
	if !auth.VerifyPassword(payload.Current, user.PasswordHash) {
		writeError(w, r, errUnauthorized("Текущий пароль неверен"))
		return
	}
	hash, err := auth.HashPassword(payload.New)
	if err != nil {
		writeError(w, r, errInternal("Пароль не обработан").Because(err))
		return
	}
	if h.Auth.SessionRepo == nil {
		writeError(w, r, errInternal("Хранилище пользователей не подключено"))
		return
	}
	if err := h.Auth.SessionRepo.UpdatePassword(r.Context(), user.ID, hash, false); err != nil {
		writeError(w, r, errInternal("Пароль не изменён").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}

func (h *AuthHandler) APITokens(w http.ResponseWriter, r *http.Request) {
	user, _ := CurrentUser(r.Context())
	if user == nil || h.Auth.SessionRepo == nil {
		writeError(w, r, errUnauthorized("Пользователь не определён"))
		return
	}
	items, err := h.Auth.SessionRepo.ListAPITokens(r.Context(), user.ID)
	if err != nil {
		writeError(w, r, errInternal("Токены не прочитаны").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *AuthHandler) CreateAPIToken(w http.ResponseWriter, r *http.Request) {
	user, _ := CurrentUser(r.Context())
	if user == nil || h.Auth.SessionRepo == nil {
		writeError(w, r, errUnauthorized("Пользователь не определён"))
		return
	}
	var payload struct {
		Name          string `json:"name"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLoginBodyBytes)).Decode(&payload); err != nil || strings.TrimSpace(payload.Name) == "" {
		writeError(w, r, errValidation("Имя токена обязательно"))
		return
	}
	var expires *time.Time
	if payload.ExpiresInDays > 0 {
		value := h.Auth.now().AddDate(0, 0, payload.ExpiresInDays)
		expires = &value
	}
	plain, hash, err := auth.NewOpaqueToken(auth.APITokenPrefix)
	if err != nil {
		writeError(w, r, errInternal("Токен не создан").Because(err))
		return
	}
	record, err := h.Auth.SessionRepo.CreateAPIToken(r.Context(), user.ID, strings.TrimSpace(payload.Name), hash, expires)
	if err != nil {
		writeError(w, r, errInternal("Токен не сохранён").Because(err))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "id": record.ID, "name": record.Name, "expires_at": record.ExpiresAt, "created_at": record.CreatedAt})
}

func (h *AuthHandler) DeleteAPIToken(w http.ResponseWriter, r *http.Request) {
	user, _ := CurrentUser(r.Context())
	if user == nil || h.Auth.SessionRepo == nil {
		writeError(w, r, errUnauthorized("Пользователь не определён"))
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "tokenID"), 10, 64)
	if err != nil {
		writeError(w, r, errValidation("Неверный id токена"))
		return
	}
	deleted, err := h.Auth.SessionRepo.DeleteAPIToken(r.Context(), user.ID, id)
	if err != nil {
		writeError(w, r, errInternal("Токен не удалён").Because(err))
		return
	}
	if !deleted {
		writeError(w, r, errNotFound("Токен не найден"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// recordLogin пишет в аудит и удачный, и неудачный вход. Неудачный — важнее:
// по нему видно подбор пароля к сервисной учётке.
func (h *AuthHandler) recordLogin(r *http.Request, action string, user *domain.User, name, result string) {
	entry := domain.AuditLog{
		ActorName:  name,
		Action:     action,
		EntityType: "user",
		EntityID:   &name,
		NewValue:   map[string]any{"result": result},
		Source:     "api",
		IP:         ClientIP(r),
		CreatedAt:  h.Auth.now(),
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if user != nil {
		entry.ActorID = &user.ID
		id := formatInt(user.ID)
		entry.EntityID = &id
		if role := auth.PrimaryRole(user.Roles); role != "" {
			entry.ActorRole = &role
		}
	}
	// Аудит пишется вне запроса клиента: его контекст к этому моменту может
	// быть уже отменён (клиент закрыл соединение), а запись о неудачном входе
	// потерять нельзя.
	ctx, cancel := contextWithTimeout(3 * time.Second)
	defer cancel()
	if err := h.Auth.Repo.InsertAuditLog(ctx, entry); err != nil {
		defaultLogger.Printf("[%s] не удалось записать аудит %q: %v", RequestID(r.Context()), action, err)
	}
}

func rolesOrEmpty(roles []string) []string {
	if roles == nil {
		return []string{}
	}
	return roles
}
