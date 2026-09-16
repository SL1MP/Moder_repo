package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"moderation/internal/policy"
)

// Справочник лицензий для автодополнения SPDX в карточке пакета.
// Порт GET /api/v1/licenses из backend/app/api/v1/packages.py.

// LicensesHandler — зависимости маршрута справочника.
type LicensesHandler struct {
	Policy *policy.LicensePolicy
}

// MountLicenses подключает справочник. Закрыт токеном, как и остальная база:
// по составу справочника видно, какие лицензии компания считает допустимыми.
func MountLicenses(r chi.Router, h *LicensesHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Get("/api/v1/licenses", h.List)
	})
}

// List — GET /api/v1/licenses.
//
// Отдаётся и при неудачной загрузке файла: поле error — единственное место,
// где интерфейс может узнать, что автодополнение пусто не потому, что
// справочник пуст, а потому что его не прочитали.
func (h *LicensesHandler) List(w http.ResponseWriter, r *http.Request) {
	p := h.Policy
	if p == nil {
		writeError(w, r, errInternal("Справочник лицензий не настроен"))
		return
	}
	payload := map[string]any{
		"path":      p.Path,
		"loaded_at": p.LoadedAt,
		"error":     nilIfEmpty(p.Err),
		"allowed":   p.SortedAllowed(),
		"forbidden": p.SortedForbidden(),
	}
	writeJSON(w, http.StatusOK, payload)
}
