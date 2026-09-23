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
	// Policies — держатель, а не загруженный справочник: POST /admin/reload
	// перечитывает файл без перезапуска сервиса, и обработчик, взявший копию
	// один раз при сборке, отдавал бы устаревший список до следующего
	// рестарта — то есть ровно то, ради отмены чего перезагрузка и заводилась.
	Policies *policy.Holder
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
	if h.Policies == nil {
		writeError(w, r, errInternal("Справочник лицензий не настроен"))
		return
	}
	p := h.Policies.Licenses()
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
