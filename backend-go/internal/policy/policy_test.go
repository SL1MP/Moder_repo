package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// Файлы политик из репозитория — не выдуманные фикстуры: если формат
// разойдётся с тем, что читает python-версия, обе версии начнут выносить
// разные вердикты по одному пакету, и заметят это на проде.
const (
	repoLicenses  = "../../../config/licenses.yml"
	repoBlacklist = "../../../config/blacklist.yml"
)

func TestLoadsRepositoryLicenses(t *testing.T) {
	p := LoadLicensePolicy(repoLicenses)
	if p.Failed() {
		t.Fatalf("справочник не прочитан: %s", p.Err)
	}
	if len(p.Allowed) == 0 || len(p.Forbidden) == 0 {
		t.Fatalf("разделы пусты: разрешено %d, запрещено %d", len(p.Allowed), len(p.Forbidden))
	}
	if !p.IsAllowed("MIT") {
		t.Error("MIT должна быть разрешена")
	}
	// Регистр в метаданных реестра приходит любой.
	if !p.IsAllowed("mit") || !p.IsAllowed("  Apache-2.0  ") {
		t.Error("сверка не должна зависеть от регистра и пробелов")
	}
	if p.IsAllowed("AGPL-3.0-only") {
		t.Error("AGPL-3.0-only в разделе forbidden — разрешать нельзя")
	}
	if p.IsAllowed("Нет-такой-лицензии") {
		t.Error("неизвестная лицензия не разрешается")
	}
}

// Составные выражения SPDX встречаются в метаданных реально (Python-пакеты
// часто «MIT OR Apache-2.0»). Без их разбора такой пакет уходил бы юристу
// каждый раз, хотя обе лицензии разрешены.
func TestCompositeLicenseExpressions(t *testing.T) {
	p := policyWith([]string{"MIT", "Apache-2.0"}, []string{"AGPL-3.0-only"})

	cases := []struct {
		expr string
		want bool
	}{
		{"MIT OR Apache-2.0", true},
		{"MIT OR AGPL-3.0-only", true},   // достаточно одной разрешённой
		{"MIT AND Apache-2.0", true},     // обе разрешены
		{"MIT AND AGPL-3.0-only", false}, // соблюдать пришлось бы и запрещённую
		{"AGPL-3.0-only OR SSPL-1.0", false},
		{"(MIT OR Apache-2.0)", true},
		{"GPL-3.0-only", false},
	}
	for _, tc := range cases {
		if got := p.IsAllowed(tc.expr); got != tc.want {
			t.Errorf("IsAllowed(%q) = %v, ожидалось %v", tc.expr, got, tc.want)
		}
	}
}

// Прямой запрет сильнее разрешения: лицензия, попавшая в оба раздела по
// недосмотру, должна остаться запрещённой.
func TestForbiddenWinsOverAllowed(t *testing.T) {
	p := policyWith([]string{"SSPL-1.0"}, []string{"SSPL-1.0"})
	if p.IsAllowed("SSPL-1.0") {
		t.Fatal("запрет должен иметь приоритет над разрешением")
	}
}

// Выражение приходит из метаданных чужого пакета, то есть это недоверенный
// ввод: глубокая вложенность не должна уводить разбор в бесконечную рекурсию.
func TestDeeplyNestedExpressionTerminates(t *testing.T) {
	p := policyWith([]string{"MIT"}, nil)
	expr := "MIT"
	for i := 0; i < 200; i++ {
		expr = "(" + expr + " OR MIT)"
	}
	// Важно только то, что вызов возвращается.
	_ = p.IsAllowed(expr)
}

// Не прочитанный справочник запрещает всё: пакет уходит юристу. Обратное
// (разрешить всё) пропустило бы AGPL и SSPL в контур молча.
func TestMissingLicenseFileDeniesEverything(t *testing.T) {
	p := LoadLicensePolicy(filepath.Join(t.TempDir(), "нет-такого.yml"))
	if !p.Failed() {
		t.Fatal("отсутствующий файл должен быть отмечен как неудача")
	}
	if p.IsAllowed("MIT") {
		t.Fatal("при непрочитанном справочнике не разрешено ничего")
	}
}

func TestBrokenYAMLIsReportedNotIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licenses.yml")
	if err := os.WriteFile(path, []byte("allowed:\n  - spdx_id: MIT\n   плохой отступ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := LoadLicensePolicy(path)
	if !p.Failed() {
		t.Fatal("битый YAML должен быть отмечен как неудача, а не прочитан как пустой файл")
	}
}

// Запись справочника бывает и строкой, и объектом — python-версия принимает оба вида.
func TestLicenseEntryAsPlainString(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licenses.yml")
	if err := os.WriteFile(path, []byte("allowed:\n  - MIT\n  - spdx_id: ISC\n    name: ISC License\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := LoadLicensePolicy(path)
	if p.Failed() {
		t.Fatalf("файл не прочитан: %s", p.Err)
	}
	if !p.IsAllowed("MIT") || !p.IsAllowed("ISC") {
		t.Fatalf("обе формы записи должны читаться: %+v", p.Allowed)
	}
	if entry, ok := p.Entry("ISC"); !ok || entry.Name != "ISC License" {
		t.Fatalf("поля объекта потерялись: %+v", entry)
	}
}

// --------------------------------------------------------------------------- blacklist

func TestLoadsRepositoryBlacklist(t *testing.T) {
	b := LoadBlacklist(repoBlacklist)
	if b.Failed() {
		t.Fatalf("правила не прочитаны: %s", b.Err)
	}
	if len(b.Rules) == 0 {
		t.Fatal("правил ноль — файл разобран неверно")
	}
	if rule := b.Find("pypi", "colourama", "0.1.0"); rule == nil {
		t.Error("тайпсквоттинг colourama должен запрещаться")
	} else if rule.Reason == "" {
		t.Error("у правила должна быть причина — её видит разработчик")
	}
	if b.Find("pypi", "colorama", "0.4.6") != nil {
		t.Error("настоящий colorama запрещать нельзя")
	}
	// Правило без manager действует на все менеджеры.
	if b.Find("npm", "internal-secrets", "1.0.0") == nil {
		t.Error("правило internal-* должно ловить dependency confusion в любом менеджере")
	}
}

func TestBlacklistVersionRanges(t *testing.T) {
	b := &Blacklist{Rules: []Rule{
		{Manager: "npm", Name: "event-stream", Versions: "==3.3.6", Reason: "бэкдор"},
		{Manager: "pypi", Name: "ranged", Versions: ">=1.0,<2.0", Reason: "диапазон"},
		{Manager: "pypi", Name: "upper", Versions: "<1.4.3", Reason: "старое"},
		{Manager: "pypi", Name: "anyver", Versions: "*", Reason: "любая"},
	}}

	cases := []struct {
		manager, name, version string
		blocked                bool
	}{
		{"npm", "event-stream", "3.3.6", true},
		{"npm", "event-stream", "3.3.5", false},
		{"pypi", "ranged", "1.5.0", true},
		{"pypi", "ranged", "2.0.0", false},
		{"pypi", "ranged", "0.9.0", false},
		{"pypi", "upper", "1.4.2", true},
		{"pypi", "upper", "1.4.3", false},
		// Сравнение версий — компаратором экосистемы, не строкой: посимвольно
		// «1.10» меньше «1.9», и правило молча перестало бы срабатывать.
		{"pypi", "upper", "1.10.0", false},
		{"pypi", "anyver", "0.0.1", true},
	}
	for _, tc := range cases {
		got := b.Find(tc.manager, tc.name, tc.version) != nil
		if got != tc.blocked {
			t.Errorf("%s %s@%s: запрещён = %v, ожидалось %v", tc.manager, tc.name, tc.version, got, tc.blocked)
		}
	}
}

func TestBlacklistManagerScope(t *testing.T) {
	b := &Blacklist{Rules: []Rule{
		{Manager: "pypi", Name: "shared", Versions: "*"},
		{Name: "everywhere", Versions: "*"},
	}}
	if b.Find("npm", "shared", "1.0.0") != nil {
		t.Error("правило с manager=pypi не должно ловить npm-пакет")
	}
	if b.Find("nuget", "everywhere", "1.0.0") == nil {
		t.Error("правило без manager должно ловить любой менеджер")
	}
}

// Не прочитанный файл правил и пустой список правил — разные вещи: в первом
// случае мы не знаем, что запрещено, и молча пропускать пакет нельзя.
func TestMissingBlacklistIsNotEmptyBlacklist(t *testing.T) {
	missing := LoadBlacklist(filepath.Join(t.TempDir(), "нет-такого.yml"))
	if !missing.Failed() {
		t.Fatal("отсутствующий файл должен быть отмечен как неудача")
	}

	path := filepath.Join(t.TempDir(), "blacklist.yml")
	if err := os.WriteFile(path, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := LoadBlacklist(path)
	if empty.Failed() {
		t.Fatalf("пустой список правил — не ошибка: %s", empty.Err)
	}
	if len(empty.Rules) != 0 {
		t.Fatalf("правил должно быть ноль, получено %d", len(empty.Rules))
	}
}

// Правило с битым glob не должно запрещать всё подряд: это опечатка в файле
// политики, а не запрет на всю базу.
func TestBrokenGlobMatchesNothing(t *testing.T) {
	b := &Blacklist{Rules: []Rule{{Name: "[", Versions: "*"}}}
	if b.Find("pypi", "requests", "2.31.0") != nil {
		t.Fatal("правило с некорректным шаблоном не должно срабатывать")
	}
}

func policyWith(allowed, forbidden []string) *LicensePolicy {
	p := &LicensePolicy{
		Allowed:   map[string]LicenseEntry{},
		Forbidden: map[string]LicenseEntry{},
	}
	for _, spdx := range allowed {
		p.Allowed[normalizeSPDX(spdx)] = LicenseEntry{SPDXID: spdx, Allowed: true}
	}
	for _, spdx := range forbidden {
		p.Forbidden[normalizeSPDX(spdx)] = LicenseEntry{SPDXID: spdx}
	}
	return p
}
