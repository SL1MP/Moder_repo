package api

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
)

const adminBodyLimit = 128 << 10

// UpdateSettings сохраняет несекретные web-настройки. Они применяются при
// restart api-go/worker-go; пересборка образов не требуется.
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
		"saved": keys,
		"restart_required": true,
		"message": "Настройки сохранены. Выполните restart api-go и worker-go; пересборка не требуется.",
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

// CreateUser создаёт локального пользователя либо заранее создаёт профиль
// OIDC-пользователя. В обоих случаях роли выдаёт само приложение.
func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string   `json:"username"`
		Email    string   `json:"email"`
		FullName string   `json:"full_name"`
		Roles    []string `json:"roles"`
		Source   string   `json:"source"`
		Password string   `json:"password"`
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
	payload.Source = strings.TrimSpace(payload.Source)
	if payload.Source == "" {
		payload.Source = "local"
	}
	if payload.Source != "local" && payload.Source != "oidc" {
		writeError(w, r, errValidation("Источник должен быть local или oidc"))
		return
	}
	roles, err := validRoles(payload.Roles)
	if err != nil {
		writeError(w, r, errValidation(err.Error()))
		return
	}
	var created *domain.User
	if payload.Source == "local" {
		if len([]rune(payload.Password)) < 8 {
			writeError(w, r, errValidation("Пароль локального пользователя должен содержать не менее 8 символов"))
			return
		}
		hash, hashErr := auth.HashPassword(payload.Password)
		if hashErr != nil {
			writeError(w, r, errInternal("Пароль пользователя не обработан").Because(hashErr))
			return
		}
		created, err = h.Repo.CreateLocalUser(r.Context(), payload.Username,
			strings.TrimSpace(payload.Email), strings.TrimSpace(payload.FullName), hash, roles, h.now())
	} else {
		created, err = h.Repo.CreateOIDCUser(r.Context(), payload.Username,
			strings.TrimSpace(payload.Email), strings.TrimSpace(payload.FullName), roles, h.now())
	}
	if err != nil {
		writeError(w, r, errConflict("Пользователь с таким логином уже существует").Because(err))
		return
	}
	actor, _ := CurrentUser(r.Context())
	h.auditAdminChange(r, actor, "user_created", "user", &created.ID, nil,
		map[string]any{"username": created.Username, "source": payload.Source, "roles": roles})
	writeJSON(w, http.StatusCreated, userAdminView(created))
}

// UpdateUser меняет роли и активность пользователя внутри сервиса.
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt64(w, r, "userID")
	if !ok {
		return
	}
	var payload struct {
		Roles    []string `json:"roles"`
		IsActive *bool    `json:"is_active"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, adminBodyLimit)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Данные доступа не разобраны").Because(err))
		return
	}
	roles, err := validRoles(payload.Roles)
	if err != nil {
		writeError(w, r, errValidation(err.Error()))
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
	updated, err := h.Repo.UpdateUserAccess(r.Context(), id, roles, active, h.now())
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
	source := "local"
	if user.PasswordHash == nil ||
		(user.Subject != nil && *user.Subject != "" && !strings.HasPrefix(*user.Subject, "local:")) {
		source = "oidc"
	}
	if user.IsService {
		source = "service"
	}
	return map[string]any{
		"id": user.ID, "username": user.Username, "email": user.Email,
		"full_name": user.FullName, "display_name": user.DisplayName(),
		"roles": rolesOrEmpty(user.Roles), "source": source,
		"is_active": user.IsActive, "last_login_at": user.LastLoginAt,
		"created_at": user.CreatedAt,
	}
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
