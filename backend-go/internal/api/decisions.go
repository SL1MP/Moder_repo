package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/auth"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/repo"
)

// Решения ролей: карантин, DevSecOps, юрист.
// Порт backend/app/api/v1/decisions.py.
//
// Решение обязано возобновить конвейер — иначе пакет остаётся стоять, а
// интерфейс показывает «решение принято». Возобновление идёт через очередь
// (internal/queue): пакет возвращается в `queued` с отметкой, с какого шага
// продолжать, и его забирает воркер.

// DecisionsHandler — зависимости маршрутов решений. Очередь сюда не входит:
// возобновление конвейера делает сам сервис решений через Resume, и знать о
// ней обработчику незачем.
type DecisionsHandler struct {
	Repo      *repo.Repo
	Decisions *decisions.Service
	Now       func() time.Time
}

func (h *DecisionsHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

const maxDecisionBodyBytes = 64 << 10

// MountDecisions подключает решения ролей. Каждое закрыто своей ролью:
// решение DevSecOps не должен принимать юрист, и наоборот.
func MountDecisions(r chi.Router, h *DecisionsHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.With(RequireRoles("devsecops")).
			Post("/api/v1/items/{itemID}/quarantine/release", h.ReleaseQuarantine)
		sub.With(RequireRoles("devsecops")).
			Post("/api/v1/items/{itemID}/security-decision", h.SecurityDecision)
		sub.With(RequireRoles("legal")).
			Post("/api/v1/license-claims/{claimID}/decision", h.LicenseDecision)
		sub.Get("/api/v1/license-claims", h.ListClaims)
		sub.Get("/api/v1/license-claims/{claimID}", h.GetClaim)
	})
}

// decisionBody — общее тело решения: одобрить или нет и почему.
type decisionBody struct {
	Approve bool   `json:"approve"`
	Comment string `json:"comment"`
}

func readDecisionBody(r *http.Request) (decisionBody, *Error) {
	var body decisionBody
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxDecisionBodyBytes))
	if err != nil {
		return body, errValidation("Тело запроса не прочитано").Because(err)
	}
	// Пустое тело допустимо там, где решение не требует полей (снятие
	// карантина): заставлять клиента слать «{}» незачем.
	if len(strings.TrimSpace(string(raw))) == 0 {
		return body, nil
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return body, errValidation("Ожидается JSON с полями approve и comment").Because(err)
	}
	if len(body.Comment) > 4000 {
		return body, errValidation("Комментарий длиннее 4000 символов")
	}
	return body, nil
}

// ReleaseQuarantine — POST /api/v1/items/{itemID}/quarantine/release.
func (h *DecisionsHandler) ReleaseQuarantine(w http.ResponseWriter, r *http.Request) {
	item, user, ok := h.itemAndUser(w, r)
	if !ok {
		return
	}
	body, bodyErr := readDecisionBody(r)
	if bodyErr != nil {
		writeError(w, r, bodyErr)
		return
	}
	result, err := h.Decisions.ReleaseQuarantine(r.Context(), item, true, body.Comment)
	h.respond(w, r, item.ID, user, result, err, "quarantine_released")
}

// SecurityDecision — POST /api/v1/items/{itemID}/security-decision.
func (h *DecisionsHandler) SecurityDecision(w http.ResponseWriter, r *http.Request) {
	item, user, ok := h.itemAndUser(w, r)
	if !ok {
		return
	}
	body, bodyErr := readDecisionBody(r)
	if bodyErr != nil {
		writeError(w, r, bodyErr)
		return
	}
	result, err := h.Decisions.DecideSecurity(r.Context(), item, body.Approve, user.ID, body.Comment)
	h.respond(w, r, item.ID, user, result, err, "decision_made")
}

// LicenseDecision — POST /api/v1/license-claims/{claimID}/decision.
//
// Решение принимается по заявлению, но применяется к пакету заявки: юрист
// смотрит на приложенную ссылку, а разблокировать надо конвейер.
func (h *DecisionsHandler) LicenseDecision(w http.ResponseWriter, r *http.Request) {
	claimID, ok := pathInt64(w, r, "claimID")
	if !ok {
		return
	}
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут решения не закрыт проверкой токена"))
		return
	}
	body, bodyErr := readDecisionBody(r)
	if bodyErr != nil {
		writeError(w, r, bodyErr)
		return
	}

	claim, err := h.Repo.GetLicenseClaim(r.Context(), claimID)
	if err != nil {
		writeError(w, r, errInternal("Заявление не прочитано").Because(err))
		return
	}
	if claim == nil {
		writeError(w, r, errNotFound("Заявление лицензии #"+strconv.FormatInt(claimID, 10)+" не найдено"))
		return
	}
	if claim.Claim.RequestItemID == nil {
		writeError(w, r, errValidation(
			"Заявление не связано с пакетом заявки — разблокировать нечего"))
		return
	}

	item, err := h.Repo.GetRequestItem(r.Context(), *claim.Claim.RequestItemID)
	if err != nil {
		writeError(w, r, errInternal("Пакет заявки не прочитан").Because(err))
		return
	}
	if item == nil {
		writeError(w, r, errNotFound("Пакет заявки из этого заявления не найден"))
		return
	}

	// Сначала отметка на заявлении: она же и защита от двойного решения —
	// второй юрист получит конфликт, а не тихо применит своё поверх чужого.
	if err := h.Repo.DecideLicenseClaim(
		r.Context(), claimID, body.Approve, user.ID, body.Comment, h.now()); err != nil {
		if errors.Is(err, repo.ErrAlreadyDecided) {
			writeError(w, r, &Error{Code: "conflict", Status: http.StatusConflict,
				Message: "По этому заявлению решение уже принято"})
			return
		}
		writeError(w, r, errInternal("Решение по заявлению не записано").Because(err))
		return
	}

	spdx := ""
	if claim.Claim.SPDXID != nil {
		spdx = *claim.Claim.SPDXID
	}
	result, err := h.Decisions.DecideLicense(
		r.Context(), item, body.Approve, user.ID, spdx, body.Comment)
	if err != nil {
		h.writeDecisionError(w, r, err)
		return
	}
	h.afterDecision(r, item.ID, user, result, "decision_made")

	updated, err := h.Repo.GetLicenseClaim(r.Context(), claimID)
	if err != nil || updated == nil {
		writeError(w, r, errInternal("Заявление после решения не прочитано").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, h.claimView(r, *updated))
}

// ListClaims — GET /api/v1/license-claims.
func (h *DecisionsHandler) ListClaims(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут заявлений не закрыт проверкой токена"))
		return
	}
	status := r.URL.Query().Get("status")
	if _, ok := r.URL.Query()["status"]; !ok {
		// По умолчанию — только нерешённые: список всех заявлений за всё
		// время юристу не нужен, ему нужна работа.
		status = "pending"
	}

	var claimedBy *int64
	if !user.HasRole("admin", "legal", "devsecops") {
		id := user.ID
		claimedBy = &id
	}
	rows, err := h.Repo.ListLicenseClaims(r.Context(), status, claimedBy)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить заявления лицензий").Because(err))
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, h.claimView(r, row))
	}
	writeJSON(w, http.StatusOK, out)
}

// GetClaim — GET /api/v1/license-claims/{claimID}.
func (h *DecisionsHandler) GetClaim(w http.ResponseWriter, r *http.Request) {
	claimID, ok := pathInt64(w, r, "claimID")
	if !ok {
		return
	}
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут заявления не закрыт проверкой токена"))
		return
	}
	row, err := h.Repo.GetLicenseClaim(r.Context(), claimID)
	if err != nil {
		writeError(w, r, errInternal("Заявление не прочитано").Because(err))
		return
	}
	if row == nil {
		writeError(w, r, errNotFound("Заявление лицензии #"+strconv.FormatInt(claimID, 10)+" не найдено"))
		return
	}
	if !user.HasRole("admin", "legal", "devsecops") && row.Claim.ClaimedByID != user.ID {
		writeError(w, r, errForbidden(
			"Заявление доступно его автору, юристам, DevSecOps и администратору"))
		return
	}
	writeJSON(w, http.StatusOK, h.claimView(r, *row))
}

// --------------------------------------------------------------------------- общее

// itemAndUser читает пакет заявки и текущего пользователя.
func (h *DecisionsHandler) itemAndUser(w http.ResponseWriter, r *http.Request) (*domain.RequestItem, *domain.User, bool) {
	itemID, ok := pathInt64(w, r, "itemID")
	if !ok {
		return nil, nil, false
	}
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут решения не закрыт проверкой токена"))
		return nil, nil, false
	}
	item, err := h.Repo.GetRequestItem(r.Context(), itemID)
	if err != nil {
		writeError(w, r, errInternal("Пакет заявки не прочитан").Because(err))
		return nil, nil, false
	}
	if item == nil {
		writeError(w, r, errNotFound("Пакет заявки #"+strconv.FormatInt(itemID, 10)+" не найден"))
		return nil, nil, false
	}
	return item, user, true
}

// respond завершает решение: обрабатывает ошибку, доводит побочные эффекты и
// отдаёт обновлённый пакет заявки.
func (h *DecisionsHandler) respond(w http.ResponseWriter, r *http.Request, itemID int64, user *domain.User, result *decisions.Result, err error, event string) {
	if err != nil {
		h.writeDecisionError(w, r, err)
		return
	}
	h.afterDecision(r, itemID, user, result, event)

	// Пакет перечитывается: решение меняет статус, и отдавать клиенту
	// состояние «до» значит показывать кнопку, которой больше нет.
	item, err := h.Repo.GetRequestItem(r.Context(), itemID)
	if err != nil || item == nil {
		writeError(w, r, errInternal("Пакет заявки после решения не прочитан").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": item.ID, "package_version_id": item.PackageVersionID,
		"name": item.RequestedName, "version": item.RequestedVersion,
		"dependency_kind": item.DependencyKind,
		"status":          item.Status, "status_title": statusTitle(item.Status),
		"current_step": item.CurrentStep, "blocked_reason": item.BlockedReason,
		"next_action": item.NextAction, "waiting_since": item.WaitingSince,
		"finished_at": item.FinishedAt,
	})
}

// writeDecisionError переводит ошибку сервиса решений в ответ API.
func (h *DecisionsHandler) writeDecisionError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, decisions.ErrConflict):
		// Пакет не в том состоянии: кто-то решил раньше, либо интерфейс
		// показывает устаревшее состояние. И то и другое — 409, а не 500.
		writeError(w, r, &Error{Code: "conflict", Status: http.StatusConflict,
			Message: strings.TrimPrefix(err.Error(), "конфликт состояния: ")})
	case errors.Is(err, decisions.ErrValidation):
		writeError(w, r, errValidation(
			strings.TrimPrefix(err.Error(), "решение сформулировано неверно: ")))
	default:
		// Схема базы отстала от кода — ошибка называет это прямо: иначе
		// «Решение не применено» отправляет искать проблему в заявке, а она
		// в развёртывании. Живой случай: решение DevSecOps не применялось,
		// потому что в базе не было столбца очереди конвейера.
		if schemaErr := schemaError(err); schemaErr != nil {
			writeError(w, r, schemaErr)
			return
		}
		writeError(w, r, errInternal("Решение не применено").Because(err))
	}
}

// afterDecision доводит побочные эффекты решения: аудит, уведомления и
// пересчёт статуса заявки.
//
// Возобновление конвейера здесь НЕ делается: его выполняет сам сервис решений
// через Resume — иначе о нём легко забыть в одном из маршрутов, и пакет
// останется стоять после нажатия кнопки.
func (h *DecisionsHandler) afterDecision(r *http.Request, itemID int64, user *domain.User, result *decisions.Result, event string) {
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()

	entityID := strconv.FormatInt(itemID, 10)
	entry := domain.AuditLog{
		ActorID: &user.ID, ActorName: user.Username,
		Action: event, EntityType: "request_item", EntityID: &entityID,
		Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
	}
	if role := auth.PrimaryRole(user.Roles); role != "" {
		entry.ActorRole = &role
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if result != nil && len(result.Siblings) > 0 {
		// Решение принимается по версии пакета, поэтому доходит и до других
		// заявок. В журнале это должно быть видно: иначе непонятно, почему
		// чужая заявка вдруг поехала дальше.
		entry.NewValue = map[string]any{"siblings": result.Siblings}
	}
	if err := h.Repo.InsertAuditLog(ctx, entry); err != nil {
		defaultLogger.Printf("[%s] аудит решения не записан: %v", RequestID(r.Context()), err)
	}

	// Уведомления и пересчёт статусов делает сервис решений: карантин снимает
	// ещё и регламентная задача, и автор заявки обязан узнать об этом ровно
	// так же, как если бы кнопку нажал DevSecOps.
	for _, err := range h.Decisions.Deliver(ctx, itemID, result) {
		defaultLogger.Printf("[%s] %v", RequestID(r.Context()), err)
	}
}

// claimView — заявление для выдачи. Снимок текста обрезается: юристу нужен
// текст лицензии, а не мегабайт страницы репозитория.
func (h *DecisionsHandler) claimView(r *http.Request, row repo.ClaimRow) map[string]any {
	c := row.Claim
	view := map[string]any{
		"id":                  c.ID,
		"package_version_id":  c.PackageVersionID,
		"request_item_id":     c.RequestItemID,
		"package":             row.PackageName,
		"version":             row.Version,
		"manager":             row.Manager,
		"url":                 c.URL,
		"spdx_id":             c.SPDXID,
		"comment":             c.Comment,
		"status":              c.Status,
		"snapshot_fetched_at": c.SnapshotFetchedAt,
		"claimed_by":          row.ClaimedBy,
		"decided_by":          row.DecidedBy,
		"decided_at":          c.DecidedAt,
		"decision_comment":    c.DecisionComment,
		"created_at":          c.CreatedAt,
	}
	if c.SnapshotText != nil {
		view["snapshot_text"] = truncateRunes(*c.SnapshotText, maxSnapshotRunes)
	} else {
		view["snapshot_text"] = nil
	}
	if spdx, _, err := h.Repo.SuggestedLicense(r.Context(), c.PackageVersionID); err == nil && spdx != "" {
		view["suggested_license"] = spdx
	} else {
		view["suggested_license"] = nil
	}
	return view
}

// maxSnapshotRunes — сколько текста лицензии показываем. Столько же, сколько
// python-версия.
const maxSnapshotRunes = 20000
