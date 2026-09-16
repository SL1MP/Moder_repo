package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/repo"
)

// Уведомления внутри сервиса. Порт backend/app/api/v1/notifications.py.

// NotificationsHandler — зависимости маршрутов уведомлений.
type NotificationsHandler struct {
	Repo *repo.Repo
	Now  func() time.Time
}

func (h *NotificationsHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

const maxMarkReadBodyBytes = 64 << 10

// MountNotifications подключает уведомления.
func MountNotifications(r chi.Router, h *NotificationsHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/api/v1/notifications", h.List)
		sub.Post("/api/v1/notifications/read", h.MarkRead)
	})
}

// List — GET /api/v1/notifications.
func (h *NotificationsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут уведомлений не закрыт проверкой токена"))
		return
	}
	q := r.URL.Query()
	limit, err := intParam(q.Get("limit"), 50)
	if err != nil || limit <= 0 {
		writeError(w, r, errValidation("Параметр limit должен быть положительным числом"))
		return
	}
	if limit > 200 {
		writeError(w, r, errValidation("Параметр limit не больше 200"))
		return
	}

	items, err := h.Repo.ListNotifications(r.Context(), user.ID, q.Get("only_unread") == "true", limit)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить уведомления").Because(err))
		return
	}
	// Счётчик непрочитанных считается отдельно от страницы: значок в меню
	// должен показывать все непрочитанные, а не сколько их попало в limit.
	unread, err := h.Repo.CountUnreadNotifications(r.Context(), user.ID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось посчитать непрочитанные").Because(err))
		return
	}

	out := make([]map[string]any, 0, len(items))
	for _, n := range items {
		out = append(out, map[string]any{
			"id":              n.ID,
			"event":           n.Event,
			"title":           n.Title,
			"body":            n.Body,
			"request_id":      n.RequestID,
			"request_item_id": n.RequestItemID,
			"created_at":      n.CreatedAt,
			"read_at":         n.ReadAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"unread": unread, "items": out})
}

// MarkRead — POST /api/v1/notifications/read.
//
// Отмечаются только свои уведомления: фильтр по пользователю стоит в запросе,
// поэтому чужой идентификатор в списке ничего не сделает, а не пометит
// прочитанным чужое.
func (h *NotificationsHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут уведомлений не закрыт проверкой токена"))
		return
	}
	var payload struct {
		IDs []int64 `json:"ids"`
		All bool    `json:"all"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMarkReadBodyBytes)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Ожидается JSON с полями ids и all").Because(err))
		return
	}
	if !payload.All && len(payload.IDs) == 0 {
		writeJSON(w, http.StatusOK, map[string]int{"updated": 0})
		return
	}

	updated, err := h.Repo.MarkNotificationsRead(
		r.Context(), user.ID, payload.IDs, payload.All, h.now())
	if err != nil {
		writeError(w, r, errInternal("Не удалось отметить уведомления").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"updated": updated})
}
