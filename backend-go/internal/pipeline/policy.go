package pipeline

import "path"

// BlacklistRule — порт backend/app/services/policies.py BlacklistRule. Сверка
// диапазонов версий (`>=1.0,<2.0` и т.п.) сознательно не перенесена в этой
// ревизии — только точная версия или `*` (любая); версионные диапазоны
// требуют per-менеджер компаратора (app/managers/versioning.py), который
// появится вместе с плагинами пакетных менеджеров (фаза 3).
type BlacklistRule struct {
	Manager  *string // nil = любой менеджер
	Name     string  // точное имя или glob
	Versions string  // "*" или точная версия
	Reason   string
}

func (r BlacklistRule) matches(manager, name, version string) bool {
	if r.Manager != nil && *r.Manager != manager {
		return false
	}
	if r.Name != name {
		if ok, _ := path.Match(r.Name, name); !ok {
			return false
		}
	}
	if r.Versions != "*" && r.Versions != "" && r.Versions != version {
		return false
	}
	return true
}

// BlacklistPolicy — источник правил blacklist. Целевая реализация — БД (см.
// docs/configuration-model.md, "Политики блокировки"), не файл конфигурации.
type BlacklistPolicy interface {
	Find(manager, name, version string) *BlacklistRule
}

// InMemoryBlacklist — простая реализация для тестов и первого прогона; не
// адаптер на будущее хранилище (то будет отдельная реализация того же
// интерфейса поверх БД).
type InMemoryBlacklist struct {
	Rules []BlacklistRule
}

func (b *InMemoryBlacklist) Find(manager, name, version string) *BlacklistRule {
	for i := range b.Rules {
		if b.Rules[i].matches(manager, name, version) {
			return &b.Rules[i]
		}
	}
	return nil
}

// LicensePolicy — порт backend/app/services/policies.py LicensePolicy.
// Составные выражения `A OR B`/`A AND B` (Python is_allowed) сознательно не
// перенесены в этой ревизии — только прямая проверка SPDX-идентификатора;
// требует отдельной проверки, насколько составные лицензии реально
// встречаются на практике, прежде чем переносить эту ветку логики.
type LicensePolicy interface {
	IsAllowed(spdxID string) bool
}

type InMemoryLicensePolicy struct {
	Allowed map[string]bool // ключ — spdxID в нижнем регистре
}

func (p *InMemoryLicensePolicy) IsAllowed(spdxID string) bool {
	if spdxID == "" {
		return false
	}
	return p.Allowed[normalizeSPDX(spdxID)]
}

func normalizeSPDX(spdxID string) string {
	out := make([]byte, len(spdxID))
	for i := 0; i < len(spdxID); i++ {
		c := spdxID[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
