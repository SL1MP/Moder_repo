package api

import (
	"encoding/json"
	"io"
	"net/http"

	"moderation/internal/policy"
)

const licensePolicyBodyLimit = 2 << 20

// UpdateLicenses — PUT /api/v1/admin/policies/licenses. Доступен юристам и
// администраторам: это бизнес-политика, а не настройка инфраструктуры.
func (h *AdminHandler) UpdateLicenses(w http.ResponseWriter, r *http.Request) {
	if h.Repo == nil || h.Policies == nil {
		writeError(w, r, errInternal("Хранилище политики лицензий не подключено"))
		return
	}
	var payload struct {
		Entries *[]policy.LicenseEntry `json:"entries"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, licensePolicyBodyLimit)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Ожидается JSON {entries: [...]} ").Because(err))
		return
	}
	if payload.Entries == nil {
		writeError(w, r, errValidation("Поле entries обязательно"))
		return
	}
	entries, err := policy.NormalizeLicenseEntries(*payload.Entries)
	if err != nil {
		writeError(w, r, errValidation(err.Error()).Because(err))
		return
	}
	actor, _ := CurrentUser(r.Context())
	if actor == nil {
		writeError(w, r, errInternal("Не определён пользователь"))
		return
	}
	before := h.Policies.Licenses()
	if err := h.Repo.SaveLicenseEntries(r.Context(), entries, actor.ID); err != nil {
		if schema := schemaError(err); schema != nil {
			writeError(w, r, schema)
			return
		}
		writeError(w, r, errInternal("Политика лицензий не сохранена").Because(err))
		return
	}
	h.Policies.ReplaceLicenses(entries, "database:license_policy")
	oldAllowed, oldForbidden := 0, 0
	if before != nil {
		oldAllowed, oldForbidden = len(before.Allowed), len(before.Forbidden)
	}
	after := h.Policies.Licenses()
	h.auditAdminChange(r, actor, "license_policy_updated", "policy", nil,
		map[string]any{"allowed": oldAllowed, "forbidden": oldForbidden},
		map[string]any{"allowed": len(after.Allowed), "forbidden": len(after.Forbidden)})
	writeJSON(w, http.StatusOK, map[string]any{
		"allowed": after.SortedAllowed(), "forbidden": after.SortedForbidden(),
		"loaded_at": after.LoadedAt,
		"message": "Политика лицензий сохранена и применяется к новым проверкам.",
	})
}
