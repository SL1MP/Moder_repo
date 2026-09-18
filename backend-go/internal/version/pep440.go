package version

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PEP440 — правила pypi: версии по PEP 440 и спецификаторы по PEP 440 §Version
// Specifiers (==, !=, >=, <=, >, <, ~=, ===, суффикс .*).
type PEP440 struct{}

func (PEP440) Name() string { return "pypi" }

// pep440Value — разобранная версия. Ключ сравнения собран по packaging: dev
// без пререлиза младше любого пререлиза, отсутствие пререлиза старше любого,
// отсутствие post младше любого post, отсутствие dev старше любого dev.
// Отсюда сентинелы вместо «нуля по умолчанию»: 1.0 и 1.0.dev1 иначе
// сравнялись бы, хотя 1.0.dev1 выходит раньше.
type pep440Value struct {
	epoch   int
	release []int
	preRank int
	preNum  int
	post    int
	dev     int
	valid   bool
}

const (
	negInfinity = math.MinInt32
	posInfinity = math.MaxInt32
)

var pep440Re = regexp.MustCompile(
	`^(?:(\d+)!)?(\d+(?:\.\d+)*)` + // epoch и release
		`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?` + // пререлиз
		`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?` + // post
		`(?:[-_.]?(dev)[-_.]?(\d+)?)?` + // dev
		`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`) // локальная версия

func parsePEP440(v string) pep440Value {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(s, "v")
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440Value{}
	}
	out := pep440Value{valid: true, preRank: posInfinity, post: negInfinity, dev: posInfinity}
	if m[1] != "" {
		out.epoch, _ = strconv.Atoi(m[1])
	}
	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return pep440Value{}
		}
		out.release = append(out.release, n)
	}
	if m[3] != "" {
		out.preRank = preLetterRank(m[3])
		if m[4] != "" {
			out.preNum, _ = strconv.Atoi(m[4])
		}
	}
	switch {
	case m[5] != "": // неявная форма post: «1.0-1»
		out.post, _ = strconv.Atoi(m[5])
	case m[6] != "": // «1.0.post2», «1.0.rev», «1.0-r3»
		out.post = 0
		if m[7] != "" {
			out.post, _ = strconv.Atoi(m[7])
		}
	}
	if m[8] != "" { // «1.0.dev», «1.0.dev3»
		out.dev = 0
		if m[9] != "" {
			out.dev, _ = strconv.Atoi(m[9])
		}
	}

	// dev без пререлиза младше любого пререлиза того же релиза.
	if out.preRank == posInfinity && out.post == negInfinity && out.dev != posInfinity {
		out.preRank = negInfinity
	}
	return out
}

func preLetterRank(letter string) int {
	switch letter {
	case "a", "alpha":
		return 0
	case "b", "beta":
		return 1
	case "c", "rc", "pre", "preview":
		return 2
	}
	return 0
}

func comparePEP440Values(a, b pep440Value) int {
	switch {
	case !a.valid && !b.valid:
		return 0
	case !a.valid:
		return -1
	case !b.valid:
		return 1
	}
	if a.epoch != b.epoch {
		return sign(a.epoch - b.epoch)
	}
	if c := compareInts(a.release, b.release); c != 0 {
		return c
	}
	if a.preRank != b.preRank {
		return sign(a.preRank - b.preRank)
	}
	if a.preNum != b.preNum {
		return sign(a.preNum - b.preNum)
	}
	if a.post != b.post {
		return sign(a.post - b.post)
	}
	if a.dev != b.dev {
		return sign(a.dev - b.dev)
	}
	return 0
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	}
	return 0
}

func (PEP440) Compare(a, b string) int { return comparePEP440Values(parsePEP440(a), parsePEP440(b)) }

func (PEP440) IsPrerelease(v string) bool {
	parsed := parsePEP440(v)
	if !parsed.valid {
		return false
	}
	return parsed.preRank != posInfinity || parsed.dev != posInfinity
}

type pep440Spec struct {
	op       string
	raw      string
	val      pep440Value
	wildcard bool // «==1.4.*»
}

var pep440SpecRe = regexp.MustCompile(`^(===|==|!=|~=|>=|<=|>|<)\s*(.+)$`)

func parsePEP440Specs(constraint string) ([]pep440Spec, error) {
	text := strings.TrimSpace(constraint)
	if text == "" {
		return nil, nil
	}
	var out []pep440Spec
	for _, chunk := range strings.Split(text, ",") {
		item := strings.TrimSpace(chunk)
		if item == "" {
			continue
		}
		m := pep440SpecRe.FindStringSubmatch(item)
		if m == nil {
			return nil, fmt.Errorf("%w: «%s» не является спецификатором PEP 440", ErrBadConstraint, item)
		}
		spec := pep440Spec{op: m[1], raw: strings.TrimSpace(m[2])}
		if strings.HasSuffix(spec.raw, ".*") {
			spec.wildcard = true
			spec.raw = strings.TrimSuffix(spec.raw, ".*")
		}
		spec.val = parsePEP440(spec.raw)
		if !spec.val.valid && spec.op != "===" {
			return nil, fmt.Errorf("%w: «%s» не является версией PEP 440", ErrBadConstraint, item)
		}
		out = append(out, spec)
	}
	return out, nil
}

func (spec pep440Spec) matches(v pep440Value, raw string) bool {
	if spec.op == "===" {
		return strings.TrimSpace(raw) == spec.raw
	}
	cmp := comparePEP440Values(v, spec.val)
	switch spec.op {
	case "==":
		if spec.wildcard {
			return releaseHasPrefix(v.release, spec.val.release)
		}
		return cmp == 0
	case "!=":
		if spec.wildcard {
			return !releaseHasPrefix(v.release, spec.val.release)
		}
		return cmp != 0
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		// PEP 440: «>V» не допускает post-релиз той же версии. «>1.7»
		// означает «следующий релиз», а 1.7.post1 — это всё ещё 1.7 с
		// исправленными метаданными, а не то, чего ждал автор требования.
		if cmp <= 0 {
			return false
		}
		if spec.val.post == negInfinity && v.post != negInfinity && sameRelease(v, spec.val) {
			return false
		}
		return true
	case "<":
		// PEP 440: «<V» не допускает пререлиз той же версии. Иначе «<2.0»
		// затянуло бы 2.0.0a1 — формально меньшую, но принадлежащую уже
		// следующему релизу.
		if cmp >= 0 {
			return false
		}
		if !hasPreOrDev(spec.val) && hasPreOrDev(v) && sameRelease(v, spec.val) {
			return false
		}
		return true
	case "~=":
		// Совместимый релиз: не ниже указанного и не выше, чем позволяет
		// отбрасывание последнего сегмента. ~=1.4.2 — это >=1.4.2, ==1.4.*.
		if cmp < 0 {
			return false
		}
		if len(spec.val.release) < 2 {
			return false
		}
		return releaseHasPrefix(v.release, spec.val.release[:len(spec.val.release)-1])
	}
	return false
}

// hasPreOrDev — версия является пререлизом или dev-сборкой.
func hasPreOrDev(v pep440Value) bool {
	return v.preRank != posInfinity || v.dev != posInfinity
}

// sameRelease — одинаковая числовая часть с точностью до хвостовых нулей:
// 2.0 и 2.0.0 — один и тот же релиз.
func sameRelease(a, b pep440Value) bool {
	return compareInts(a.release, b.release) == 0
}

func releaseHasPrefix(release, prefix []int) bool {
	for i, want := range prefix {
		var got int
		if i < len(release) {
			got = release[i]
		}
		if got != want {
			return false
		}
	}
	return true
}

func (p PEP440) Satisfies(constraint, v string) (bool, error) {
	parsed := parsePEP440(v)
	if !parsed.valid {
		return false, nil
	}
	specs, err := parsePEP440Specs(constraint)
	if err != nil {
		return false, err
	}
	for _, spec := range specs {
		if !spec.matches(parsed, v) {
			return false, nil
		}
	}
	return true, nil
}

// specsAllowPrerelease — требование само упоминает пререлиз. По PEP 440
// пререлизы не подставляются автоматически: «>=2.0» не означает «2.1rc1».
func specsAllowPrerelease(specs []pep440Spec) bool {
	for _, spec := range specs {
		if spec.val.valid && (spec.val.preRank != posInfinity || spec.val.dev != posInfinity) {
			return true
		}
	}
	return false
}

func (p PEP440) Select(constraint string, available []string) (string, error) {
	specs, err := parsePEP440Specs(constraint)
	if err != nil {
		return "", err
	}
	match := func(v string) (bool, error) { return p.Satisfies(constraint, v) }
	allowPre := specsAllowPrerelease(specs)
	selected, err := selectHighest(p, match, available, allowPre)
	if err == nil || allowPre {
		return selected, err
	}
	// У пакета может не быть ни одного стабильного релиза — тогда пререлиз
	// лучше, чем потерянная зависимость.
	return selectHighest(p, match, available, true)
}
