package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"moderation/internal/policy"
)

// UpdateBlacklist — PUT /api/v1/admin/policies/blacklist.
//
// Клиент присылает весь список: сервер проверяет его целиком, сохраняет одним
// JSONB-документом и только после успешного COMMIT подменяет рабочую политику.
// Поэтому ошибочная строка не применит половину изменений.
func (h *AdminHandler) UpdateBlacklist(w http.ResponseWriter, r *http.Request) {
	if h.Repo == nil || h.Policies == nil {
		writeError(w, r, errInternal("Хранилище blacklist не подключено"))
		return
	}
	var payload struct {
		Rules *[]policy.Rule `json:"rules"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, adminBodyLimit)).Decode(&payload); err != nil {
		writeError(w, r, errValidation("Ожидается JSON {rules: [...]} ").Because(err))
		return
	}
	if payload.Rules == nil {
		writeError(w, r, errValidation("Поле rules обязательно; пустой массив отключает все правила"))
		return
	}
	rules, err := policy.NormalizeBlacklistRules(*payload.Rules)
	if err != nil {
		writeError(w, r, errValidation(err.Error()).Because(err))
		return
	}
	actor, _ := CurrentUser(r.Context())
	if actor == nil {
		writeError(w, r, errInternal("Не определён администратор"))
		return
	}

	before := h.Policies.Blacklist()
	rules = blacklistAuditFields(rules, before, actor.Username, h.now())
	if err := h.Repo.SaveBlacklistRules(r.Context(), rules, actor.ID); err != nil {
		if schema := schemaError(err); schema != nil {
			writeError(w, r, schema)
			return
		}
		writeError(w, r, errInternal("Blacklist не сохранён").Because(err))
		return
	}
	h.Policies.ReplaceBlacklist(rules, "database:blacklist_policy")

	beforeCount := 0
	if before != nil {
		beforeCount = len(before.Rules)
	}
	h.auditAdminChange(r, actor, "blacklist_updated", "policy", nil,
		map[string]any{"rules": beforeCount}, map[string]any{"rules": len(rules)})
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": rules,
		"loaded_at": h.Policies.Blacklist().LoadedAt,
		"message": "Blacklist сохранён и применяется к новым проверкам.",
	})
}

func blacklistAuditFields(
	rules []policy.Rule, before *policy.Blacklist, actor string, now time.Time,
) []policy.Rule {
	previous := map[string]policy.Rule{}
	if before != nil {
		for _, rule := range before.Rules {
			previous[blacklistRuleKey(rule)] = rule
		}
	}
	for i := range rules {
		if old, ok := previous[blacklistRuleKey(rules[i])]; ok {
			if old.AddedBy != "" && old.AddedAt != "" {
				rules[i].AddedBy = old.AddedBy
				rules[i].AddedAt = old.AddedAt
				continue
			}
		}
		rules[i].AddedBy = actor
		rules[i].AddedAt = now.UTC().Format("2006-01-02")
	}
	return rules
}

func blacklistRuleKey(rule policy.Rule) string {
	return rule.Manager + "\x00" + rule.Name + "\x00" + rule.Versions
}
