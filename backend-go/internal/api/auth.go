package api

import (
	"encoding/json"
	"io"
	"net/http"
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
		sub.With(h.Auth.Authenticate).Get("/me", h.Me)
	})
}

// Config — GET /api/v1/auth/config. Параметры OIDC для SPA
// (Authorization Code + PKCE).
func (h *AuthHandler) Config(w http.ResponseWriter, r *http.Request) {
	cfg := h.Cfg
	writeJSON(w, http.StatusOK, map[string]any{
		// Издатель здесь ВНЕШНИЙ: по нему в Keycloak пойдёт браузер, а не
		// сервис. Подстановка внутреннего адреса — самая частая причина
		// «кнопка входа ведёт в никуда».
		"issuer":             cfg.BrowserIssuer(),
		"client_id":          cfg.OIDCClientID,
		"scopes":             []string{"openid", "profile", "email"},
		"flow":               "authorization_code_pkce",
		"local_auth_enabled": cfg.LocalAuthEnabled,
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
		"id":           user.ID,
		"username":     user.Username,
		"display_name": user.DisplayName(),
		"email":        user.Email,
		"roles":        rolesOrEmpty(user.Roles),
		"is_service":   user.IsService,
		// Маршруты GitLab пока ведёт python-версия; сюда отдаём только факт
		// привязки, чтобы SPA рисовала одно и то же независимо от того, какая
		// версия ответила.
		"gitlab_connected": user.GitlabRefreshTokenEnc != nil || user.GitlabAccessTokenEnc != nil,
	})
}

// LocalLogin — POST /api/v1/auth/token. Fallback-вход только для сервисных
// учёток, в prod выключен флагом LOCAL_AUTH_ENABLED.
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

	user, err := h.Auth.Repo.GetUserByUsername(r.Context(), payload.Username)
	if err != nil {
		writeError(w, r, errInternal("Не удалось проверить учётную запись").Because(err))
		return
	}

	// Ответ на неверный логин и на неверный пароль одинаков намеренно: иначе
	// по разнице ответов перебирается список существующих учёток.
	if user == nil || !user.IsActive || !auth.VerifyPassword(payload.Password, user.PasswordHash) {
		h.recordLogin(r, "local_login_failed", nil, payload.Username, "denied")
		writeError(w, r, errUnauthorized("Неверный логин или пароль"))
		return
	}

	token, ttl, err := h.Auth.Verifier.IssueLocalToken(user)
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

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   ttl,
		"roles":        rolesOrEmpty(user.Roles),
	})
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
