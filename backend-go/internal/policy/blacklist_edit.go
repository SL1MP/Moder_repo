package policy

import (
	"fmt"
	"path"
	"strings"

	"moderation/internal/domain"
)

const MaxBlacklistRules = 5000

// NormalizeBlacklistRules проверяет и нормализует полный список из web.
// Проверка выполняется до записи всего документа: одно неверное правило не
// должно оставить в базе частично обновлённую политику.
func NormalizeBlacklistRules(input []Rule) ([]Rule, error) {
	if len(input) > MaxBlacklistRules {
		return nil, fmt.Errorf("правил больше допустимого предела %d", MaxBlacklistRules)
	}
	managers := make(map[string]struct{}, len(domain.ManagerCodes))
	for _, manager := range domain.ManagerCodes {
		managers[manager] = struct{}{}
	}
	seen := make(map[string]struct{}, len(input))
	out := make([]Rule, 0, len(input))
	for i, raw := range input {
		rule := Rule{
			Manager: strings.ToLower(strings.TrimSpace(raw.Manager)),
			Name: strings.TrimSpace(raw.Name), Versions: strings.TrimSpace(raw.Versions),
			Reason: strings.TrimSpace(raw.Reason), AddedBy: strings.TrimSpace(raw.AddedBy),
			AddedAt: strings.TrimSpace(raw.AddedAt),
		}
		if rule.Manager != "" {
			if _, ok := managers[rule.Manager]; !ok {
				return nil, fmt.Errorf("правило %d: неизвестный менеджер %q", i+1, rule.Manager)
			}
		}
		if rule.Name == "" {
			return nil, fmt.Errorf("правило %d: имя или glob обязателен", i+1)
		}
		if len(rule.Name) > 512 {
			return nil, fmt.Errorf("правило %d: имя или glob длиннее 512 символов", i+1)
		}
		if _, err := path.Match(rule.Name, "blacklist-validation-probe"); err != nil {
			return nil, fmt.Errorf("правило %d: неверный glob имени: %w", i+1, err)
		}
		if rule.Versions == "" {
			rule.Versions = "*"
		}
		if len(rule.Versions) > 256 {
			return nil, fmt.Errorf("правило %d: условие версии длиннее 256 символов", i+1)
		}
		if err := validateVersionSpec(rule.Versions); err != nil {
			return nil, fmt.Errorf("правило %d: %w", i+1, err)
		}
		if rule.Reason == "" {
			rule.Reason = "Пакет запрещён правилами blacklist"
		}
		if len(rule.Reason) > 2000 {
			return nil, fmt.Errorf("правило %d: причина длиннее 2000 символов", i+1)
		}
		key := rule.Manager + "\x00" + rule.Name + "\x00" + rule.Versions
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("правило %d дублирует менеджер, имя и версии", i+1)
		}
		seen[key] = struct{}{}
		out = append(out, rule)
	}
	return out, nil
}

func validateVersionSpec(spec string) error {
	switch strings.ToLower(spec) {
	case "*", "all", "any":
		return nil
	}
	for _, clause := range strings.Split(spec, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			return fmt.Errorf("условие версии содержит пустую часть")
		}
		_, bound := splitClause(clause)
		if strings.TrimSpace(bound) == "" {
			return fmt.Errorf("в условии версии %q отсутствует значение", clause)
		}
	}
	return nil
}
