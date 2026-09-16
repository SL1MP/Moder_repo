// Package policy — blacklist и справочник разрешённых лицензий из файлов
// конфигурации. Порт backend/app/services/policies.py.
//
// Оба файла монтируются в контейнер (`./config:/config:ro`) и читаются при
// старте. Общий с python-версией формат и общие файлы — обязательное условие:
// обе версии выносят вердикт по одному пакету, и разойтись в том, какая
// лицензия разрешена и какой пакет запрещён, они не имеют права.
//
// Ошибка чтения не роняет сервис, но и не проходит молча — см. Failed().
package policy

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"moderation/internal/osv"
)

// --------------------------------------------------------------------------- лицензии

// LicenseEntry — запись справочника лицензий.
//
// Поля отдаются всегда, без omitempty: python-версия кладёт в них null, а не
// опускает ключ, и потребитель справочника рассчитывает на его присутствие.
// Пустая строка вместо null здесь равнозначна — единственное место, где это
// поле читают (выпадающий список SPDX в карточке пакета), сравнивает его с
// spdx_id и одинаково обрабатывает "", null и undefined.
type LicenseEntry struct {
	SPDXID  string `json:"spdx_id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Notes   string `json:"notes"`
	Allowed bool   `json:"allowed"`
}

// LicensePolicy — справочник SPDX: что разрешено, что запрещено прямо.
type LicensePolicy struct {
	// Ключ — SPDX-идентификатор в нижнем регистре.
	Allowed   map[string]LicenseEntry
	Forbidden map[string]LicenseEntry
	Path      string
	LoadedAt  time.Time
	// Err — почему справочник не загрузился. Пустая строка — загрузился.
	Err string
}

// Failed — справочник не загрузился.
func (p *LicensePolicy) Failed() bool { return p != nil && p.Err != "" }

// IsAllowed — разрешена ли лицензия. Порт LicensePolicy.is_allowed.
//
// Не загрузившийся справочник запрещает всё: пустой список разрешённых
// лицензий отправляет каждый пакет юристу. Это шумно, но безопасно — обратное
// (разрешить всё) пропустило бы в контур AGPL и SSPL молча.
func (p *LicensePolicy) IsAllowed(spdx string) bool {
	return p.isAllowed(spdx, 0)
}

// maxExpressionDepth — предел вложенности составного выражения. Выражения
// приходят из метаданных чужого пакета, то есть это недоверенный ввод:
// без предела «A OR (B OR (C OR …))» уводит разбор в глубокую рекурсию.
const maxExpressionDepth = 8

func (p *LicensePolicy) isAllowed(spdx string, depth int) bool {
	if p == nil || depth > maxExpressionDepth {
		return false
	}
	key := normalizeSPDX(spdx)
	if key == "" {
		return false
	}
	if _, forbidden := p.Forbidden[key]; forbidden {
		return false
	}
	if _, ok := p.Allowed[key]; ok {
		return true
	}

	// Составное выражение SPDX. `A OR B` — достаточно одной разрешённой:
	// правообладатель даёт выбор, и мы выбираем разрешённую. `A AND B`
	// требует обе: соблюдать придётся обе.
	if parts := splitExpression(key, " or "); len(parts) > 1 {
		for _, part := range parts {
			if p.isAllowed(part, depth+1) {
				return true
			}
		}
		return false
	}
	if parts := splitExpression(key, " and "); len(parts) > 1 {
		for _, part := range parts {
			if !p.isAllowed(part, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// Entry — запись справочника по идентификатору, из любого раздела.
func (p *LicensePolicy) Entry(spdx string) (LicenseEntry, bool) {
	key := normalizeSPDX(spdx)
	if entry, ok := p.Allowed[key]; ok {
		return entry, true
	}
	entry, ok := p.Forbidden[key]
	return entry, ok
}

// SortedAllowed и SortedForbidden — записи для выдачи в API, по алфавиту:
// обход map в Go случаен, а справочник читает человек.
func (p *LicensePolicy) SortedAllowed() []LicenseEntry   { return sortedEntries(p.Allowed) }
func (p *LicensePolicy) SortedForbidden() []LicenseEntry { return sortedEntries(p.Forbidden) }

func sortedEntries(m map[string]LicenseEntry) []LicenseEntry {
	out := make([]LicenseEntry, 0, len(m))
	for _, entry := range m {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SPDXID < out[j].SPDXID })
	return out
}

func splitExpression(key, sep string) []string {
	if !strings.Contains(key, sep) {
		return nil
	}
	parts := strings.Split(key, sep)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.Trim(strings.TrimSpace(part), "()"))
	}
	return out
}

func normalizeSPDX(spdx string) string {
	return strings.ToLower(strings.TrimSpace(spdx))
}

// --------------------------------------------------------------------------- blacklist

// Rule — правило blacklist.
type Rule struct {
	Manager  string // пустая строка — любой менеджер
	Name     string // точное имя или glob
	Versions string // "*", точная версия или диапазон ">=1.0,<2.0"
	Reason   string
	AddedBy  string
	AddedAt  string
}

// Blacklist — правила запрета пакетов.
type Blacklist struct {
	Rules    []Rule
	Path     string
	LoadedAt time.Time
	Err      string
}

// Failed — правила не загрузились. ВАЖНО: пустой список правил и не
// загрузившийся файл — разные вещи. В первом случае запрещать нечего, во
// втором мы не знаем, что запрещено, и молча пропускать пакет нельзя.
func (b *Blacklist) Failed() bool { return b != nil && b.Err != "" }

// Find — первое подходящее правило. nil, если пакет не запрещён.
func (b *Blacklist) Find(manager, name, version string) *Rule {
	if b == nil {
		return nil
	}
	for i := range b.Rules {
		if b.Rules[i].Matches(manager, name, version) {
			return &b.Rules[i]
		}
	}
	return nil
}

// Matches — подходит ли правило под пакет.
func (r Rule) Matches(manager, name, version string) bool {
	if r.Manager != "" && r.Manager != manager {
		return false
	}
	if r.Name != name {
		// Ошибка в шаблоне — опечатка в файле политики, а не совпадение:
		// правило с битым шаблоном не должно запрещать всё подряд.
		if ok, err := path.Match(r.Name, name); err != nil || !ok {
			return false
		}
	}
	return versionInSpec(manager, version, r.Versions)
}

// versionInSpec — диапазон версий: `*`, `1.2.3`, `>=1.0`, `>=1.0,<2.0`, `<1.4.3`.
// Порт _version_in_spec. Сравнение — компаратором экосистемы, а не строковое:
// для pypi «1.10» больше «1.9», а посимвольно — меньше.
func versionInSpec(manager, version, spec string) bool {
	spec = strings.TrimSpace(spec)
	switch strings.ToLower(spec) {
	case "*", "", "all", "any":
		return true
	}
	compare := osv.ComparatorFor(manager)
	for _, clause := range strings.Split(spec, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		op, bound := splitClause(clause)
		result := compare(version, bound)
		ok := false
		switch op {
		case ">=":
			ok = result >= 0
		case "<=":
			ok = result <= 0
		case "==", "":
			ok = result == 0
		case "!=":
			ok = result != 0
		case ">":
			ok = result > 0
		case "<":
			ok = result < 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// splitClause отделяет оператор от границы. Порядок проверки важен: «>=»
// должен проверяться раньше «>», иначе от «>=1.0» останется «=1.0».
func splitClause(clause string) (op, bound string) {
	for _, candidate := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if strings.HasPrefix(clause, candidate) {
			return candidate, strings.TrimSpace(strings.TrimPrefix(clause, candidate))
		}
	}
	return "", clause
}

// --------------------------------------------------------------------------- чтение файлов

// LoadLicensePolicy читает справочник лицензий. Ошибка не возвращается
// отдельно: сервис обязан подняться и с непрочитанным файлом, а факт ошибки
// остаётся в Err и виден в API и в логе.
func LoadLicensePolicy(filePath string) *LicensePolicy {
	policy := &LicensePolicy{
		Allowed: map[string]LicenseEntry{}, Forbidden: map[string]LicenseEntry{},
		Path: filePath, LoadedAt: time.Now().UTC(),
	}
	var doc struct {
		Allowed   []licenseNode `yaml:"allowed"`
		Forbidden []licenseNode `yaml:"forbidden"`
	}
	if err := readYAML(filePath, &doc); err != nil {
		policy.Err = err.Error()
		return policy
	}
	collect(policy.Allowed, doc.Allowed, true)
	collect(policy.Forbidden, doc.Forbidden, false)
	return policy
}

// licenseNode — запись справочника. В файле она бывает и строкой («MIT»), и
// объектом, поэтому разбирается вручную.
type licenseNode struct {
	SPDXID string `yaml:"spdx_id"`
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Notes  string `yaml:"notes"`
}

func (n *licenseNode) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		return value.Decode(&n.SPDXID)
	}
	type plain licenseNode // без этого UnmarshalYAML вызвал бы сам себя
	return value.Decode((*plain)(n))
}

func collect(dst map[string]LicenseEntry, nodes []licenseNode, allowed bool) {
	for _, node := range nodes {
		spdx := strings.TrimSpace(node.SPDXID)
		if spdx == "" {
			spdx = strings.TrimSpace(node.ID)
		}
		if spdx == "" {
			continue
		}
		dst[normalizeSPDX(spdx)] = LicenseEntry{
			SPDXID: spdx, Name: node.Name, URL: node.URL, Notes: node.Notes, Allowed: allowed,
		}
	}
}

// LoadBlacklist читает правила запрета.
func LoadBlacklist(filePath string) *Blacklist {
	list := &Blacklist{Path: filePath, LoadedAt: time.Now().UTC()}
	var doc struct {
		Rules []struct {
			Manager  string `yaml:"manager"`
			Name     string `yaml:"name"`
			Versions string `yaml:"versions"`
			Reason   string `yaml:"reason"`
			AddedBy  string `yaml:"added_by"`
			AddedAt  string `yaml:"added_at"`
		} `yaml:"rules"`
	}
	if err := readYAML(filePath, &doc); err != nil {
		list.Err = err.Error()
		return list
	}
	for _, raw := range doc.Rules {
		name := strings.TrimSpace(raw.Name)
		if name == "" {
			// Правило без имени ничего не запрещает, но и молчать о нём
			// нельзя: это опечатка в файле политики.
			continue
		}
		versions := strings.TrimSpace(raw.Versions)
		if versions == "" {
			versions = "*"
		}
		reason := strings.TrimSpace(raw.Reason)
		if reason == "" {
			reason = "Пакет запрещён правилами blacklist"
		}
		list.Rules = append(list.Rules, Rule{
			Manager: strings.TrimSpace(raw.Manager), Name: name, Versions: versions,
			Reason: reason, AddedBy: raw.AddedBy, AddedAt: raw.AddedAt,
		})
	}
	return list
}

// maxPolicyFileBytes — потолок на файл политики. Файл монтируется снаружи, и
// читать его без ограничения в память нельзя.
const maxPolicyFileBytes = 8 << 20

func readYAML(filePath string, dst any) error {
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("путь к файлу политики не задан")
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("файл %s не прочитан: %w", filePath, err)
	}
	if info.Size() > maxPolicyFileBytes {
		return fmt.Errorf("файл %s больше %d байт", filePath, maxPolicyFileBytes)
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("файл %s не прочитан: %w", filePath, err)
	}
	if err := yaml.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("файл %s не разбирается как YAML: %w", filePath, err)
	}
	return nil
}
