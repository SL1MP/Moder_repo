package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/repo"
)

const adminBodyLimit = 128 << 10

// UpdateSettings сохраняет несекретные web-настройки. Транзакционный NOTIFY
// после сохранения инициирует корректный автоматический перезапуск api-go и
// worker-go; вручную перезапускать или пересобирать их не требуется.
func (h *AdminHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if h.Repo == nil || h.Cfg == nil {
		writeError(w, r, errInternal("Хранилище настроек не подключено"))
		return
	}
	var payload struct {
		Values map[string]string `json:"values"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, adminBodyLimit)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Ожидается JSON {values: {KEY: value}}").Because(err))
		return
	}
	if len(payload.Values) == 0 {
		writeError(w, r, errValidation("Не передано ни одной настройки"))
		return
	}
	if err := config.ValidateOverrides(payload.Values); err != nil {
		writeError(w, r, errValidation(err.Error()).Because(err))
		return
	}
	user, _ := CurrentUser(r.Context())
	if user == nil {
		writeError(w, r, errInternal("Не определён администратор"))
		return
	}
	before, err := h.Repo.AppSettings(r.Context())
	if err != nil {
		writeError(w, r, errInternal("Текущие web-настройки не прочитаны").Because(err))
		return
	}
	if err := h.Repo.SaveAppSettings(r.Context(), payload.Values, user.ID); err != nil {
		writeError(w, r, errInternal("Настройки не сохранены").Because(err))
		return
	}

	keys := make([]string, 0, len(payload.Values))
	for key := range payload.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h.auditAdminChange(r, user, "settings_updated", "settings", nil,
		map[string]any{"values": selectedSettings(before, keys)},
		map[string]any{"values": selectedSettings(payload.Values, keys)})
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":             keys,
		"restart_required":  false,
		"restart_scheduled": true,
		"message":           "Настройки сохранены и применяются автоматически. Сервисы кратковременно перезапустятся.",
	})
}

func selectedSettings(values map[string]string, keys []string) map[string]string {
	out := map[string]string{}
	for _, key := range keys {
		if value, ok := values[key]; ok {
			out[key] = value
		}
	}
	return out
}

// Users — все локальные и OIDC-пользователи приложения.
func (h *AdminHandler) Users(w http.ResponseWriter, r *http.Request) {
	users, err := h.Repo.ListUsers(r.Context())
	if err != nil {
		writeError(w, r, errInternal("Пользователи не прочитаны").Because(err))
		return
	}
	out := make([]map[string]any, 0, len(users))
	for i := range users {
		out = append(out, userAdminView(&users[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "roles": domain.Roles})
}

// CreateUser создаёт только локального пользователя. OIDC-
// пользователь автоматически появляется после первого подтверждённого входа.
func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username           string   `json:"username"`
		Email              string   `json:"email"`
		FullName           string   `json:"full_name"`
		Roles              []string `json:"roles"`
		Password           string   `json:"password"`
		IsSuperuser        bool     `json:"is_superuser"`
		MustChangePassword bool     `json:"must_change_password"`
		Description        string   `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, adminBodyLimit)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Данные пользователя не разобраны").Because(err))
		return
	}
	payload.Username = strings.TrimSpace(payload.Username)
	if payload.Username == "" {
		writeError(w, r, errValidation("Логин обязателен"))
		return
	}
	if len([]rune(payload.Password)) < 6 {
		writeError(w, r, errValidation("Пароль локального пользователя должен содержать не менее 6 символов"))
		return
	}
	if payload.IsSuperuser && !domain.Contains(payload.Roles, "admin") {
		payload.Roles = append(payload.Roles, "admin")
	}
	roles, err := validRoles(payload.Roles)
	if err != nil {
		writeError(w, r, errValidation(err.Error()))
		return
	}
	hash, hashErr := auth.HashPassword(payload.Password)
	if hashErr != nil {
		writeError(w, r, errInternal("Пароль пользователя не обработан").Because(hashErr))
		return
	}
	payload.IsSuperuser = domain.Contains(roles, "admin")
	created, err := h.Repo.CreateLocalUserWithProfile(r.Context(), payload.Username,
		strings.TrimSpace(payload.Email), strings.TrimSpace(payload.FullName), hash, roles,
		payload.MustChangePassword, strings.TrimSpace(payload.Description), h.now())
	if err != nil {
		writeError(w, r, errConflict("Пользователь с таким логином уже существует").Because(err))
		return
	}
	actor, _ := CurrentUser(r.Context())
	h.auditAdminChange(r, actor, "user_created", "user", &created.ID, nil,
		map[string]any{"username": created.Username, "source": "local", "roles": roles,
			"is_superuser": payload.IsSuperuser, "must_change_password": payload.MustChangePassword})
	writeJSON(w, http.StatusCreated, userAdminView(created))
}

// UpdateUser меняет роли и активность пользователя внутри сервиса.
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt64(w, r, "userID")
	if !ok {
		return
	}
	var payload struct {
		Username           *string  `json:"username"`
		Email              *string  `json:"email"`
		FullName           *string  `json:"full_name"`
		Description        *string  `json:"description"`
		Roles              []string `json:"roles"`
		IsSuperuser        *bool    `json:"is_superuser"`
		IsActive           *bool    `json:"is_active"`
		Password           string   `json:"password"`
		MustChangePassword bool     `json:"must_change_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, adminBodyLimit)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Данные доступа не разобраны").Because(err))
		return
	}
	existing, err := h.Repo.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, r, errInternal("Пользователь не прочитан").Because(err))
		return
	}
	if existing == nil {
		writeError(w, r, errNotFound("Пользователь не найден"))
		return
	}
	roles := existing.Roles
	if payload.Roles != nil {
		roles, err = validRoles(payload.Roles)
	}
	if err != nil {
		writeError(w, r, errValidation(err.Error()))
		return
	}
	if payload.IsSuperuser != nil {
		if *payload.IsSuperuser && !domain.Contains(roles, "admin") {
			roles = append(roles, "admin")
		}
		if !*payload.IsSuperuser {
			roles = withoutRole(roles, "admin")
		}
	}
	active := existing.IsActive
	if payload.IsActive != nil {
		active = *payload.IsActive
	}
	if existing.HasRole("admin") && (!domain.Contains(roles, "admin") || !active) {
		count, err := h.Repo.CountActiveUsersWithRole(r.Context(), "admin")
		if err != nil {
			writeError(w, r, errInternal("Не удалось проверить администраторов").Because(err))
			return
		}
		if count <= 1 {
			writeError(w, r, errConflict("Нельзя отключить или разжаловать последнего администратора"))
			return
		}
	}
	username := existing.Username
	if payload.Username != nil && strings.TrimSpace(*payload.Username) != "" {
		username = strings.TrimSpace(*payload.Username)
	}
	email := derefString(existing.Email)
	if payload.Email != nil {
		email = strings.TrimSpace(*payload.Email)
	}
	fullName := derefString(existing.FullName)
	if payload.FullName != nil {
		fullName = strings.TrimSpace(*payload.FullName)
	}
	description := existing.Description
	if payload.Description != nil {
		description = strings.TrimSpace(*payload.Description)
	}
	var passwordHash *string
	if payload.Password != "" {
		if existing.Source != "local" {
			writeError(w, r, errForbidden("Пароль OIDC-пользователя управляется Keycloak"))
			return
		}
		if len([]rune(payload.Password)) < 6 {
			writeError(w, r, errValidation("Пароль должен содержать не менее 6 символов"))
			return
		}
		hash, hashErr := auth.HashPassword(payload.Password)
		if hashErr != nil {
			writeError(w, r, errInternal("Пароль не обработан").Because(hashErr))
			return
		}
		passwordHash = &hash
	}
	// Профиль, права и новый пароль сохраняются одним UPDATE. Иначе ошибка при
	// проверке/записи пароля могла вернуть 4xx/5xx уже после частично
	// применённых изменений пользователя.
	updated, err := h.Repo.UpdateUserProfile(r.Context(), id, username, email, fullName, description,
		roles, active, passwordHash, payload.MustChangePassword, h.now())
	if err != nil {
		writeError(w, r, errInternal("Доступ пользователя не обновлён").Because(err))
		return
	}
	if updated == nil {
		writeError(w, r, errNotFound("Пользователь уже удалён"))
		return
	}
	actor, _ := CurrentUser(r.Context())
	h.auditAdminChange(r, actor, "user_access_updated", "user", &id,
		map[string]any{"roles": existing.Roles, "is_active": existing.IsActive},
		map[string]any{"roles": updated.Roles, "is_active": updated.IsActive})
	writeJSON(w, http.StatusOK, userAdminView(updated))
}

func validRoles(values []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, role := range values {
		role = strings.TrimSpace(role)
		if role == "" || seen[role] {
			continue
		}
		if !domain.Contains(domain.Roles, role) {
			return nil, &validationMessage{"неизвестная роль: " + role}
		}
		seen[role] = true
		out = append(out, role)
	}
	sort.Strings(out)
	return out, nil
}

type validationMessage struct{ message string }

func (e *validationMessage) Error() string { return e.message }

func userAdminView(user *domain.User) map[string]any {
	source := user.Source
	if user.IsService {
		source = "service"
	}
	return map[string]any{
		"id": user.ID, "username": user.Username, "email": user.Email,
		"full_name": user.FullName, "display_name": user.DisplayName(),
		"roles": rolesOrEmpty(user.Roles), "source": source,
		"is_active": user.IsActive, "last_login_at": user.LastLoginAt,
		"is_superuser": user.IsSuperuser, "must_change_password": user.MustChangePassword,
		"description": user.Description,
		"created_at":  user.CreatedAt,
	}
}

func withoutRole(values []string, remove string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}
func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (h *AdminHandler) OIDCSettings(w http.ResponseWriter, r *http.Request) {
	value, err := h.Repo.OIDCSettings(r.Context())
	if err != nil {
		writeError(w, r, errInternal("OIDC-настройки не прочитаны").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": value.Enabled, "issuer": value.Issuer, "client_id": value.ClientID,
		"secret_set": value.ClientSecret != "", "public_base_url": value.PublicBaseURL, "button_label": value.ButtonLabel,
		"redirect_uri": oidcRedirectURI(value, r), "updated_at": value.UpdatedAt})
}

func (h *AdminHandler) UpdateOIDCSettings(w http.ResponseWriter, r *http.Request) {
	var payload repo.OIDCSettings
	if err := json.NewDecoder(io.LimitReader(r.Body, adminBodyLimit)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("OIDC-настройки не разобраны").Because(err))
		return
	}
	payload.Issuer = strings.TrimRight(strings.TrimSpace(payload.Issuer), "/")
	payload.ClientID = strings.TrimSpace(payload.ClientID)
	payload.PublicBaseURL = strings.TrimRight(strings.TrimSpace(payload.PublicBaseURL), "/")
	payload.ButtonLabel = strings.TrimSpace(payload.ButtonLabel)
	if payload.Enabled && (payload.Issuer == "" || payload.ClientID == "") {
		writeError(w, r, errValidation("issuer и client_id обязательны для включения OIDC"))
		return
	}
	if payload.Issuer != "" && !validHTTPBaseURL(payload.Issuer) {
		writeError(w, r, errValidation("issuer должен быть абсолютным http(s) URL"))
		return
	}
	if payload.PublicBaseURL != "" && !validHTTPBaseURL(payload.PublicBaseURL) {
		writeError(w, r, errValidation("public_base_url должен быть абсолютным http(s) URL"))
		return
	}
	if err := h.Repo.UpdateOIDCSettings(r.Context(), payload); err != nil {
		writeError(w, r, errInternal("OIDC-настройки не сохранены").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func validHTTPBaseURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

func (h *AdminHandler) auditAdminChange(
	r *http.Request, actor *domain.User, action, entityType string,
	entityNumericID *int64, oldValue, newValue map[string]any,
) {
	if actor == nil || h.Repo == nil {
		return
	}
	var entityID *string
	if entityNumericID != nil {
		value := formatInt(*entityNumericID)
		entityID = &value
	}
	entry := domain.AuditLog{
		ActorID: &actor.ID, ActorName: actor.Username, Action: action,
		EntityType: entityType, EntityID: entityID, OldValue: oldValue, NewValue: newValue,
		Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
	}
	if role := auth.PrimaryRole(actor.Roles); role != "" {
		entry.ActorRole = &role
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
		defaultLogger.Printf("[%s] аудит %s не записан: %v", RequestID(r.Context()), action, err)
	}
}
