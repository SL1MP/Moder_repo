// Package osv — источник данных об уязвимостях и сопоставление версий с
// диапазонами записей OSV. Порт backend/app/adapters/vuln_index.py и
// backend/app/managers/versioning.py.
//
// Каждая экосистема считает версии по-своему, поэтому у диапазонов OSV нет
// общего компаратора: `1.0.0-rc1 < 1.0.0` в semver, `1.0rc1 < 1.0` в PEP 440,
// `1.0.0-rc.1 < 1.0.0` в NuGet, а Go добавляет префикс `v` и `+incompatible`.
package osv

import (
	"regexp"
	"strconv"
	"strings"
)

// Ecosystems — имена экосистем в терминах OSV.
var Ecosystems = map[string]string{
	"pypi": "PyPI", "npm": "npm",
}

// ManagerByEcosystem — обратное отображение, по нижнему регистру.
var ManagerByEcosystem = func() map[string]string {
	out := make(map[string]string, len(Ecosystems))
	for manager, ecosystem := range Ecosystems {
		out[strings.ToLower(ecosystem)] = manager
	}
	return out
}()

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

var (
	semverRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?(?:\+([0-9A-Za-z.\-]+))?$`)
	nugetRe  = regexp.MustCompile(`^(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$`)
	// PEP 440 в объёме, который реально встречается в реестре: числовая часть,
	// необязательный pre-release (a/b/rc), post и dev.
	pep440Re = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[0-9A-Za-z.]+)?$`)
)

// Comparator — сравнение версий одной экосистемы: -1, 0, 1.
type Comparator func(a, b string) int

// ComparatorFor — компаратор менеджера; для незнакомого менеджера —
// лексикографическое сравнение (как в Python-версии).
func ComparatorFor(manager string) Comparator {
	switch manager {
	case "pypi":
		return ComparePEP440
	case "npm":
		return CompareSemver
	case "go":
		return CompareGo
	case "nuget":
		return CompareNuGet
	default:
		return cmpString
	}
}

// comparePrerelease — пустой prerelease старше любого непустого
// (1.0.0 > 1.0.0-rc.1). Числовые идентификаторы младше алфавитных.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := a[i], b[i]
		xn, xErr := strconv.Atoi(x)
		yn, yErr := strconv.Atoi(y)
		var c int
		switch {
		case xErr == nil && yErr == nil:
			c = cmpInt(xn, yn)
		case xErr == nil:
			c = -1 // числовой идентификатор младше алфавитного
		case yErr == nil:
			c = 1
		default:
			c = cmpString(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func splitPre(pre string) []string {
	if pre == "" {
		return nil
	}
	return strings.Split(pre, ".")
}

// CompareSemver — semver с необязательными minor и patch.
func CompareSemver(a, b string) int {
	ma := semverRe.FindStringSubmatch(strings.TrimSpace(a))
	mb := semverRe.FindStringSubmatch(strings.TrimSpace(b))
	if ma == nil || mb == nil {
		return cmpString(a, b)
	}
	for i := 1; i <= 3; i++ {
		if c := cmpInt(atoiOrZero(ma[i]), atoiOrZero(mb[i])); c != 0 {
			return c
		}
	}
	return comparePrerelease(splitPre(ma[4]), splitPre(mb[4]))
}

// CompareGo — Go-модули: `vX.Y.Z`, `+incompatible`, псевдоверсии.
func CompareGo(a, b string) int {
	return CompareSemver(
		strings.ReplaceAll(a, "+incompatible", ""),
		strings.ReplaceAll(b, "+incompatible", ""),
	)
}

// CompareNuGet — до четырёх числовых компонент плюс prerelease.
func CompareNuGet(a, b string) int {
	ma := nugetRe.FindStringSubmatch(strings.TrimSpace(a))
	mb := nugetRe.FindStringSubmatch(strings.TrimSpace(b))
	if ma == nil || mb == nil {
		return cmpString(a, b)
	}
	na, nb := padTo(splitInts(ma[1]), 4), padTo(splitInts(mb[1]), 4)
	for i := range na {
		if c := cmpInt(na[i], nb[i]); c != 0 {
			return c
		}
	}
	return comparePrerelease(splitPre(ma[2]), splitPre(mb[2]))
}

// ComparePEP440 — правила Python: 1.0 == 1.0.0, rc младше релиза, post старше,
// dev младше всего.
func ComparePEP440(a, b string) int {
	ma := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(a)))
	mb := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(b)))
	if ma == nil || mb == nil {
		return cmpString(a, b)
	}
	// Числовая часть: 1.0 и 1.0.0 эквивалентны, поэтому хвост дополняется нулями.
	na, nb := splitInts(ma[1]), splitInts(mb[1])
	length := len(na)
	if len(nb) > length {
		length = len(nb)
	}
	na, nb = padTo(na, length), padTo(nb, length)
	for i := range na {
		if c := cmpInt(na[i], nb[i]); c != 0 {
			return c
		}
	}
	if c := cmpInt(pep440PreRank(ma[2]), pep440PreRank(mb[2])); c != 0 {
		return c
	}
	if c := cmpInt(atoiOrZero(ma[3]), atoiOrZero(mb[3])); c != 0 {
		return c
	}
	// post: его отсутствие младше любого post.
	if c := cmpInt(boolRank(ma[4] != ""), boolRank(mb[4] != "")); c != 0 {
		return c
	}
	if c := cmpInt(atoiOrZero(ma[5]), atoiOrZero(mb[5])); c != 0 {
		return c
	}
	// dev: его наличие МЛАДШЕ отсутствия (1.0.dev1 < 1.0).
	if c := cmpInt(boolRank(ma[6] == ""), boolRank(mb[6] == "")); c != 0 {
		return c
	}
	return cmpInt(atoiOrZero(ma[7]), atoiOrZero(mb[7]))
}

// pep440PreRank — a < b < rc < релиз. Отсутствие pre-release — самый старший.
func pep440PreRank(pre string) int {
	switch pre {
	case "a", "alpha":
		return 0
	case "b", "beta":
		return 1
	case "c", "rc", "pre", "preview":
		return 2
	default:
		return 3
	}
}

func boolRank(v bool) int {
	if v {
		return 1
	}
	return 0
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func splitInts(s string) []int {
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		out = append(out, atoiOrZero(p))
	}
	return out
}

func padTo(values []int, length int) []int {
	for len(values) < length {
		values = append(values, 0)
	}
	return values
}
