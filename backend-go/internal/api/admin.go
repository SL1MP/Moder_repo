package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/auth"
	"moderation/internal/domain"
	"moderation/internal/policy"
	"moderation/internal/repo"
)

// Административные маршруты.
//
// Перезагрузка политик закрывает долг, отмеченный в status.md: правка
// config/blacklist.yml требовала перезапуска api-go, а перезапуск рвёт
// открытые запросы — и происходит это ровно тогда, когда blacklist правят
// второпях, чтобы срочно запретить пакет.

// AdminHandler — зависимости административных маршрутов.
type AdminHandler struct {
	// Policies — держатель политик, общий с конвейером: перезагрузка обязана
	// менять то, по чему проверяются пакеты, а не отдельную копию для API.
	Policies *policy.Holder
	Repo     *repo.Repo
	Now      func() time.Time
}

func (h *AdminHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

// MountAdmin подключает административные маршруты. Только admin: перезагрузка
// политик меняет то, по каким правилам проверяются все пакеты сразу.
func MountAdmin(r chi.Router, h *AdminHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Use(RequireRoles("admin"))
		sub.Post("/api/v1/admin/reload", h.Reload)
	})
}

// Reload — POST /api/v1/admin/reload
//
// Перечитывает blacklist и справочник лицензий с диска.
//
// Код ответа различает исходы: 200 — оба файла прочитаны, 422 — хотя бы один
// сломан. Отдавать 200 на сломанный файл нельзя: администратор увидел бы
// «перезагружено» и ушёл, а работать продолжали бы прежние правила.
func (h *AdminHandler) Reload(w http.ResponseWriter, r *http.Request) {
	if h.Policies == nil {
		writeError(w, r, errInternal("Политики не подключены к сервису"))
		return
	}

	result := h.Policies.Reload()

	// Перезагрузка меняет правила проверки для всех пакетов сразу — в журнале
	// аудита обязан остаться след, кто и когда это сделал.
	if user, ok := CurrentUser(r.Context()); ok && user != nil && h.Repo != nil {
		entry := domain.AuditLog{
			ActorID: &user.ID, ActorName: user.Username,
			Action: "policies_reloaded", EntityType: "policy",
			Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
			NewValue: map[string]any{
				"blacklist_rules":  result.BlacklistRules,
				"licenses_allowed": result.LicensesAllow,
				"blacklist_error":  result.BlacklistError,
				"licenses_error":   result.LicensesError,
				"ok":               result.OK(),
			},
		}
		if role := auth.PrimaryRole(user.Roles); role != "" {
			entry.ActorRole = &role
		}
		if rid := RequestID(r.Context()); rid != "" {
			entry.RequestID = &rid
		}
		if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
			// Не повод отвечать ошибкой: политики уже перечитаны, и сообщить
			// об этом важнее, чем о ненаписанной строке журнала.
			defaultLogger.Printf("[%s] аудит перезагрузки политик не записан: %v",
				RequestID(r.Context()), err)
		}
	}

	status := http.StatusOK
	if !result.OK() {
		// Прежние правила при этом остались действовать — сломанный файл их
		// не подменяет (см. policy.Holder.Reload). Сказать об этом надо
		// прямо, иначе «не перезагрузилось» читается как «правил больше нет».
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]any{
		"ok":     result.OK(),
		"result": result,
		"note": "Сломанный файл не подменяет прежние правила: если перезагрузка не удалась, " +
			"продолжают действовать те, что были загружены раньше.",
	})
}
