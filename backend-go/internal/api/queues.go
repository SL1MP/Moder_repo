package api

import (
	"math"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/repo"
)

// Очереди ролей. Порт GET /queue/security и /queue/legal из
// backend/app/api/v1/decisions.py.

// QueuesHandler — зависимости маршрутов очередей.
type QueuesHandler struct {
	Repo *repo.Repo
	Now  func() time.Time
}

func (h *QueuesHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

// MountQueues подключает очереди. Каждая закрыта своей ролью: очередь юриста
// не должна открываться разработчиком, и наоборот. admin вхож в обе.
func MountQueues(r chi.Router, h *QueuesHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.With(RequireRoles("devsecops")).Get("/api/v1/queue/security", h.Security)
		sub.With(RequireRoles("legal")).Get("/api/v1/queue/legal", h.Legal)
		// Счётчики видит любой: по ним рисуются значки в меню, и роль там
		// проверяется отдельно — каждый видит только свои счётчики.
		sub.Get("/api/v1/queue/counters", h.Counters)
	})
}

// Security — GET /api/v1/queue/security.
//
// Карантин входит в ту же очередь: снять его досрочно может только DevSecOps,
// и отдельного экрана под это нет.
func (h *QueuesHandler) Security(w http.ResponseWriter, r *http.Request) {
	h.queue(w, r,
		[]string{"awaiting_security", "quarantined"},
		// sast_scan в списке нет: SAST информационный, решения DevSecOps по
		// нему не требуется, и пакет не должен попадать в очередь из-за него.
		[]string{"vuln_scan", "banner_scan", "quarantine"})
}

// Legal — GET /api/v1/queue/legal.
func (h *QueuesHandler) Legal(w http.ResponseWriter, r *http.Request) {
	h.queue(w, r, []string{"awaiting_legal", "license_claimed"}, []string{"license"})
}

func (h *QueuesHandler) queue(w http.ResponseWriter, r *http.Request, statuses, steps []string) {
	rows, err := h.Repo.QueueItems(r.Context(), statuses, steps)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить очередь").Because(err))
		return
	}
	now := h.now()
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := row.Item
		out = append(out, map[string]any{
			"item_id":          item.ID,
			"request_id":       item.RequestID,
			"manager":          row.Manager,
			"name":             item.RequestedName,
			"version":          item.RequestedVersion,
			"status":           item.Status,
			"status_title":     statusTitle(item.Status),
			"current_step":     item.CurrentStep,
			"blocked_reason":   item.BlockedReason,
			"waiting_since":    item.WaitingSince,
			"waiting_hours":    waitingHours(item.WaitingSince, now),
			"author":           row.Author,
			"license_spdx":     row.LicenseSPDX,
			"max_vuln_score":   row.MaxVulnScore,
			"license_claim_id": row.LicenseClaimID,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// waitingHours — сколько часов пакет ждёт решения, с одним знаком после
// запятой (как в python-версии). null, если ожидание ещё не началось.
func waitingHours(since *time.Time, now time.Time) any {
	if since == nil {
		return nil
	}
	hours := now.Sub(*since).Hours()
	return math.Round(hours*10) / 10
}

// Counters — GET /api/v1/queue/counters. Значки в меню.
//
// Счётчики очередей отдаются только тем, у кого есть соответствующая роль:
// разработчику знать размер очереди юристов незачем, и показывать ему пустой
// значок хуже, чем не показывать никакого.
func (h *QueuesHandler) Counters(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		writeError(w, r, errInternal("Маршрут счётчиков не закрыт проверкой токена"))
		return
	}
	unread, err := h.Repo.CountUnreadNotifications(r.Context(), user.ID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить счётчики").Because(err))
		return
	}
	counters := map[string]int{"unread_notifications": unread}

	count := func(key string, statuses ...string) error {
		n, err := h.Repo.CountItemsByStatus(r.Context(), statuses)
		if err != nil {
			return err
		}
		counters[key] = n
		return nil
	}
	if user.HasRole("admin", "devsecops") {
		if err := count("security", "awaiting_security"); err != nil {
			writeError(w, r, errInternal("Не удалось получить счётчики").Because(err))
			return
		}
		if err := count("quarantined", "quarantined"); err != nil {
			writeError(w, r, errInternal("Не удалось получить счётчики").Because(err))
			return
		}
	}
	if user.HasRole("admin", "legal") {
		if err := count("legal", "awaiting_legal", "license_claimed"); err != nil {
			writeError(w, r, errInternal("Не удалось получить счётчики").Because(err))
			return
		}
	}
	writeJSON(w, http.StatusOK, counters)
}
