package api

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/repo"
)

// Обсуждения: ветка на заявку и на каждый её пакет.
// Порт backend/app/api/v1/comments.py.

// CommentsHandler — зависимости маршрутов обсуждения.
type CommentsHandler struct {
	Repo *repo.Repo
	Cfg  *config.Config
	Now  func() time.Time
}

func (h *CommentsHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

// maxCommentBodyBytes — потолок на тело запроса. Само сообщение ограничено
// 10000 символами, но читать неограниченный поток нельзя и до проверки длины.
const maxCommentBodyBytes = 128 << 10

// maxCommentRunes — предел длины сообщения, тот же, что у python-версии.
// Считается в символах, а не в байтах: 10000 байт кириллицы — это 5000 букв,
// и лимит вёл бы себя по-разному для разных языков.
const maxCommentRunes = 10000

// mentionRE — упоминание @логин. Отрицательный просмотр назад на \w и / не
// выражается в RE2, поэтому граница проверяется вручную, см. parseMentions.
var mentionRE = regexp.MustCompile(`@([A-Za-z0-9._\-]{2,64})`)

// MountComments подключает обсуждения.
func MountComments(r chi.Router, h *CommentsHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/api/v1/requests/{requestID}/comments", h.List)
		sub.Post("/api/v1/requests/{requestID}/comments", h.Add)
		sub.Patch("/api/v1/comments/{commentID}", h.Edit)
		sub.Delete("/api/v1/comments/{commentID}", h.Delete)
	})
}

// List — GET /api/v1/requests/{id}/comments.
func (h *CommentsHandler) List(w http.ResponseWriter, r *http.Request) {
	requestID, ok := pathInt64(w, r, "requestID")
	if !ok {
		return
	}
	user, req, ok := h.participant(w, r, requestID)
	if !ok {
		return
	}
	_ = req

	var itemID *int64
	if raw := r.URL.Query().Get("request_item_id"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			writeError(w, r, errValidation("Параметр request_item_id должен быть числом"))
			return
		}
		itemID = &parsed
	}

	rows, err := h.Repo.ListComments(r.Context(), requestID, itemID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить обсуждение").Because(err))
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, h.commentView(row, user))
	}
	writeJSON(w, http.StatusOK, out)
}

// Add — POST /api/v1/requests/{id}/comments.
func (h *CommentsHandler) Add(w http.ResponseWriter, r *http.Request) {
	requestID, ok := pathInt64(w, r, "requestID")
	if !ok {
		return
	}
	user, req, ok := h.participant(w, r, requestID)
	if !ok {
		return
	}

	var payload struct {
		Body          string `json:"body"`
		RequestItemID *int64 `json:"request_item_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCommentBodyBytes)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Ожидается JSON с полем body").Because(err))
		return
	}
	body := strings.TrimSpace(payload.Body)
	if body == "" {
		writeError(w, r, errValidation("Сообщение не может быть пустым"))
		return
	}
	if len([]rune(body)) > maxCommentRunes {
		writeError(w, r, errValidation("Сообщение длиннее 10000 символов"))
		return
	}

	// Ветка пакета: пакет обязан принадлежать этой заявке, иначе сообщение
	// уехало бы в чужое обсуждение.
	if payload.RequestItemID != nil {
		item, err := h.Repo.GetRequestItem(r.Context(), *payload.RequestItemID)
		if err != nil {
			writeError(w, r, errInternal("Не удалось проверить пакет заявки").Because(err))
			return
		}
		if item == nil || item.RequestID != requestID {
			writeError(w, r, errNotFound("Пакет заявки не найден"))
			return
		}
	}

	mentions := parseMentions(body)
	role := auth.PrimaryRole(user.Roles)
	comment := domain.Comment{
		RequestID: requestID, RequestItemID: payload.RequestItemID,
		AuthorID: user.ID, Body: body, Mentions: mentions,
	}
	if role != "" {
		comment.AuthorRole = &role
	}

	row, err := h.Repo.CreateComment(r.Context(), comment)
	if err != nil {
		writeError(w, r, errInternal("Не удалось добавить сообщение").Because(err))
		return
	}

	h.audit(r, "comment_added", row.Comment.ID, user, nil,
		map[string]any{"request_id": requestID, "request_item_id": payload.RequestItemID})
	h.notify(r, row.Comment, req, user, mentions)

	writeJSON(w, http.StatusOK, h.commentView(*row, user))
}

// Edit — PATCH /api/v1/comments/{id}.
func (h *CommentsHandler) Edit(w http.ResponseWriter, r *http.Request) {
	commentID, ok := pathInt64(w, r, "commentID")
	if !ok {
		return
	}
	user, row, ok := h.ownComment(w, r, commentID)
	if !ok {
		return
	}

	var payload struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCommentBodyBytes)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Ожидается JSON с полем body").Because(err))
		return
	}
	body := strings.TrimSpace(payload.Body)
	if body == "" {
		writeError(w, r, errValidation("Сообщение не может быть пустым"))
		return
	}
	if len([]rune(body)) > maxCommentRunes {
		writeError(w, r, errValidation("Сообщение длиннее 10000 символов"))
		return
	}

	// Правка внутри окна — обычная опечатка, помечать её незачем. Позже —
	// пометка «изменено» и запись в аудит: собеседники уже прочитали текст.
	now := h.now()
	markEdited := now.Sub(row.Comment.CreatedAt) > h.Cfg.CommentEditWindow

	updated, err := h.Repo.UpdateCommentBody(r.Context(), commentID, body, markEdited, now)
	if err != nil {
		writeError(w, r, errInternal("Не удалось изменить сообщение").Because(err))
		return
	}
	h.audit(r, "comment_edited", commentID, user,
		map[string]any{"body": row.Comment.Body},
		map[string]any{"body": body, "marked_edited": updated.Comment.IsEdited})

	writeJSON(w, http.StatusOK, h.commentView(*updated, user))
}

// Delete — DELETE /api/v1/comments/{id}. Сообщение помечается удалённым, но
// строка остаётся: на неё ссылается аудит.
func (h *CommentsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	commentID, ok := pathInt64(w, r, "commentID")
	if !ok {
		return
	}
	user, row, ok := h.ownComment(w, r, commentID)
	if !ok {
		return
	}
	updated, err := h.Repo.SoftDeleteComment(r.Context(), commentID, h.now())
	if err != nil {
		writeError(w, r, errInternal("Не удалось удалить сообщение").Because(err))
		return
	}
	h.audit(r, "comment_deleted", commentID, user,
		map[string]any{"body": row.Comment.Body}, map[string]any{"deleted": true})
	writeJSON(w, http.StatusOK, h.commentView(*updated, user))
}

// participant — доступ к обсуждению: автор заявки, DevSecOps, юрист, admin.
func (h *CommentsHandler) participant(w http.ResponseWriter, r *http.Request, requestID int64) (*domain.User, *domain.ModerationRequest, bool) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут обсуждения не закрыт проверкой токена"))
		return nil, nil, false
	}
	req, err := h.Repo.GetModerationRequest(r.Context(), requestID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось прочитать заявку").Because(err))
		return nil, nil, false
	}
	if req == nil {
		writeError(w, r, errNotFound("Заявка #"+strconv.FormatInt(requestID, 10)+" не найдена"))
		return nil, nil, false
	}
	if !user.HasRole("admin", "devsecops", "legal") && req.AuthorID != user.ID {
		writeError(w, r, errForbidden("Обсуждение доступно участникам заявки"))
		return nil, nil, false
	}
	return user, req, true
}

// ownComment — своё сообщение (или любое, если admin) и оно ещё не удалено.
func (h *CommentsHandler) ownComment(w http.ResponseWriter, r *http.Request, commentID int64) (*domain.User, *repo.CommentRow, bool) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут обсуждения не закрыт проверкой токена"))
		return nil, nil, false
	}
	row, err := h.Repo.GetComment(r.Context(), commentID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось прочитать сообщение").Because(err))
		return nil, nil, false
	}
	if row == nil {
		writeError(w, r, errNotFound("Сообщение #"+strconv.FormatInt(commentID, 10)+" не найдено"))
		return nil, nil, false
	}
	if row.Comment.DeletedAt != nil {
		writeError(w, r, errValidation("Сообщение уже удалено"))
		return nil, nil, false
	}
	if row.Comment.AuthorID != user.ID && !user.HasRole("admin") {
		writeError(w, r, errForbidden("Изменять и удалять можно только свои сообщения"))
		return nil, nil, false
	}
	return user, row, true
}

// commentView — сообщение для выдачи. Текст удалённого наружу не уходит:
// строка остаётся ради аудита, но читателю показывать её нечего.
func (h *CommentsHandler) commentView(row repo.CommentRow, user *domain.User) map[string]any {
	c := row.Comment
	body := c.Body
	if c.DeletedAt != nil {
		body = "Сообщение удалено"
	}
	author := "—"
	if row.Author != nil && *row.Author != "" {
		author = *row.Author
	}
	return map[string]any{
		"id":              c.ID,
		"request_id":      c.RequestID,
		"request_item_id": c.RequestItemID,
		"author":          author,
		"author_role":     c.AuthorRole,
		"body":            body,
		"mentions":        listOrEmpty(c.Mentions),
		"is_edited":       c.IsEdited,
		"edited_at":       c.EditedAt,
		"deleted":         c.DeletedAt != nil,
		"created_at":      c.CreatedAt,
		"can_edit":        c.DeletedAt == nil && (c.AuthorID == user.ID || user.HasRole("admin")),
	}
}

// notify — уведомления по добавленному сообщению: автору заявки, упомянутым и
// тем, кто уже писал в ветку. Себе уведомление не приходит.
func (h *CommentsHandler) notify(r *http.Request, c domain.Comment, req *domain.ModerationRequest, author *domain.User, mentions []string) {
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()

	var recipients []int64
	if req.AuthorID != author.ID {
		recipients = append(recipients, req.AuthorID)
	}
	if len(mentions) > 0 {
		ids, err := h.Repo.UserIDsByUsernames(ctx, mentions)
		if err != nil {
			defaultLogger.Printf("[%s] упомянутые не найдены: %v", RequestID(r.Context()), err)
		}
		recipients = append(recipients, without(ids, author.ID)...)
	}
	prior, err := h.Repo.CommentAuthorIDs(ctx, req.ID)
	if err != nil {
		defaultLogger.Printf("[%s] участники обсуждения не прочитаны: %v", RequestID(r.Context()), err)
	}
	recipients = append(recipients, without(prior, author.ID)...)

	label := "заявка #" + strconv.FormatInt(req.ID, 10)
	requestID := req.ID
	body := author.DisplayName() + ": " + truncateRunes(c.Body, 200)
	notification := domain.Notification{
		Event:         "comment_added",
		Title:         "Новое сообщение в обсуждении: " + label,
		Body:          &body,
		RequestID:     &requestID,
		RequestItemID: c.RequestItemID,
		Payload:       map[string]any{"comment_id": c.ID, "mentions": listOrEmpty(mentions)},
		CreatedAt:     h.now(),
	}
	if _, err := h.Repo.InsertNotifications(ctx, recipients, notification); err != nil {
		// Не повод отменять уже добавленное сообщение: оно в обсуждении есть,
		// а недоставленное уведомление — потеря меньшая, чем потерянный текст.
		defaultLogger.Printf("[%s] уведомления по сообщению #%d не созданы: %v",
			RequestID(r.Context()), c.ID, err)
	}
}

func (h *CommentsHandler) audit(r *http.Request, action string, commentID int64, user *domain.User, oldValue, newValue map[string]any) {
	ctx, cancel := contextWithTimeout(3 * time.Second)
	defer cancel()
	entityID := strconv.FormatInt(commentID, 10)
	entry := domain.AuditLog{
		ActorID: &user.ID, ActorName: user.Username,
		Action: action, EntityType: "comment", EntityID: &entityID,
		OldValue: oldValue, NewValue: newValue,
		Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
	}
	if role := auth.PrimaryRole(user.Roles); role != "" {
		entry.ActorRole = &role
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if err := h.Repo.InsertAuditLog(ctx, entry); err != nil {
		defaultLogger.Printf("[%s] аудит %q не записан: %v", RequestID(r.Context()), action, err)
	}
}

// parseMentions — логины из @упоминаний, без повторов и по алфавиту.
//
// Граница слева проверяется вручную: python-версия использует отрицательный
// просмотр назад `(?<![\w/])`, которого нет в RE2. Без него «user@example.com»
// и «https://host/@scope» давали бы ложное упоминание.
func parseMentions(body string) []string {
	seen := map[string]bool{}
	for _, loc := range mentionRE.FindAllStringSubmatchIndex(body, -1) {
		start := loc[0]
		if start > 0 {
			prev := rune(body[start-1])
			if prev == '/' || prev == '_' || isWordRune(prev) {
				continue
			}
		}
		seen[body[loc[2]:loc[3]]] = true
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func isWordRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func truncateRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit])
}

func without(ids []int64, exclude int64) []int64 {
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id != exclude {
			out = append(out, id)
		}
	}
	return out
}
