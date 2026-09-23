package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"moderation/internal/artifactstore"
	"moderation/internal/auth"
	"moderation/internal/decisions"
	"moderation/internal/domain"
)

// POST /api/v1/packages/{versionID}/revoke — отзыв одобренного пакета.
//
// Порт backend/app/api/v1/packages.py::revoke_package. Сам отзыв уже
// перенесён вместе с перепроверкой по новой базе (decisions.RevokeVersion) —
// здесь только обработчик.
//
// Единственное действие сервиса, отменяющее ранее принятое решение, и потому
// оно громкое: пакет снимается с публикации, все заявки с этой версией
// переводятся в «отозван», авторы получают уведомление, причина уходит в
// журнал. Тихий отзыв хуже отсутствующего — разработчик продолжит ставить
// пакет и не узнает, почему он вдруг перестал существовать.

// revokeBody — тело запроса.
//
// Причина принимается в двух полях. Интерфейс шлёт «comment» — он использует
// ту же форму, что для решений ролей, — а внешние вызовы естественнее пишут
// «reason». Принимаем оба: менять формат, который уже отправляет работающий
// интерфейс, при переносе нельзя.
type revokeBody struct {
	// Reason — причина отзыва. Обязательна: её увидят авторы всех заявок с
	// этой версией, и без неё отзыв невозможно объяснить ни им, ни себе через
	// полгода.
	Reason string `json:"reason"`
	// Comment — то же самое под именем, которое шлёт интерфейс.
	Comment string `json:"comment"`
	// Unpublish — снимать ли пакет с публикации в артефактори. По умолчанию
	// да; false нужен там, где артефактори недоступно: статус всё равно надо
	// поменять, иначе сервис показывает одобренным то, что уже отозвано.
	Unpublish *bool `json:"unpublish"`
}

// Revoke — POST /api/v1/packages/{versionID}/revoke
func (h *PackagesHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	versionID, ok := pathInt64(w, r, "versionID")
	if !ok {
		return
	}
	user, ok := CurrentUser(r.Context())
	if !ok || user == nil {
		writeError(w, r, errUnauthorized("Маршрут закрыт: пользователь не опознан"))
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCheckBodyBytes))
	if err != nil {
		writeError(w, r, errValidation("Тело запроса не прочитано").Because(err))
		return
	}
	var body revokeBody
	if err := json.Unmarshal(raw, &body); err != nil {
		writeError(w, r, errValidation("Ожидается JSON с полем reason").Because(err))
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = strings.TrimSpace(body.Comment)
	}
	if reason == "" {
		writeError(w, r, errValidation(
			"Причина отзыва обязательна: её увидят авторы всех заявок с этой версией"))
		return
	}

	row, err := h.Repo.GetVersionRow(r.Context(), versionID)
	if err != nil {
		writeError(w, r, errInternal("Версия пакета не прочитана").Because(err))
		return
	}
	if row == nil {
		writeError(w, r, errNotFound("Версии пакета нет в базе"))
		return
	}

	unpublish := true
	if body.Unpublish != nil {
		unpublish = *body.Unpublish
	}
	// Артефактори может быть не настроено (сервис поднимается и без него):
	// тогда снимать с публикации нечем, но статус поменять всё равно надо.
	var store artifactstore.Store
	if h.Artifacts != nil {
		store = h.Artifacts
	} else {
		unpublish = false
	}

	result, err := h.Decisions.RevokeVersion(r.Context(), decisions.RevokeInput{
		Version:     &row.Version,
		Manager:     row.Manager,
		Name:        row.Name,
		DisplayName: row.DisplayName,
		Reason:      strings.TrimSpace(body.Reason),
		ActorID:     &user.ID,
		ActorName:   user.Username,
		Source:      "ui",
		Unpublish:   unpublish,
	}, store)
	if err != nil {
		writeDecisionsError(w, r, err)
		return
	}

	h.auditRevoke(r, versionID, user, reason, result)

	// Поля status и reason — как у python-версии: их читает интерфейс.
	payload := map[string]any{
		"package_version_id": versionID,
		"status":             "revoked",
		"reason":             reason,
		"revoked_items":      result.Items,
		"unpublished":        result.Unpublished,
	}
	// Неудачное снятие с публикации — НЕ ошибка отзыва: статус уже изменён, и
	// откатывать его нельзя. Но и умолчать нельзя: копия могла остаться в
	// артефактори, и администратор обязан об этом узнать.
	if result.UnpublishError != nil {
		payload["unpublish_error"] = result.UnpublishError.Error()
		payload["note"] = "Пакет отозван в базе, но снять его с публикации не удалось — " +
			"проверьте артефактори и удалите копию вручную."
	}
	writeJSON(w, http.StatusOK, payload)
}

// auditRevoke пишет отзыв в журнал. Ошибка записи не отменяет отзыв: он уже
// состоялся, и сообщить об этом важнее, чем о ненаписанной строке журнала.
func (h *PackagesHandler) auditRevoke(
	r *http.Request, versionID int64, user *domain.User, reason string, result *decisions.RevokeResult,
) {
	if h.Repo == nil {
		return
	}
	entityID := strconv.FormatInt(versionID, 10)
	entry := domain.AuditLog{
		ActorID: &user.ID, ActorName: user.Username,
		Action: "package_revoked", EntityType: "package_version", EntityID: &entityID,
		Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
		NewValue: map[string]any{
			"reason": reason, "items": result.Items, "unpublished": result.Unpublished,
		},
	}
	if role := auth.PrimaryRole(user.Roles); role != "" {
		entry.ActorRole = &role
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
		defaultLogger.Printf("[%s] аудит отзыва не записан: %v", RequestID(r.Context()), err)
	}
}
