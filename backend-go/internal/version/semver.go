package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Semver — правила npm: semver 2.0.0 и диапазоны npm (^, ~, x, дефисные
// диапазоны, объединение через ||).
type Semver struct{}

func (Semver) Name() string { return "npm" }

// semverValue — разобранная версия. build-метаданные («+sha») в сравнении не
// участвуют по спецификации semver, поэтому не хранятся.
type semverValue struct {
	nums  [3]int
	pre   []string
	valid bool
}

func parseSemver(v string) semverValue {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return semverValue{}
	}
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return semverValue{}
	}
	out := semverValue{valid: true}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semverValue{}
		}
		out.nums[i] = n
	}
	if pre != "" {
		out.pre = strings.Split(pre, ".")
	}
	return out
}

// comparePre — порядок пререлизных идентификаторов по semver §11: версия без
// пререлиза старше, числовые идентификаторы младше текстовых, более длинный
// набор старше при равном префиксе.
func comparePre(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		default:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func compareSemverValues(a, b semverValue) int {
	switch {
	case !a.valid && !b.valid:
		return 0
	case !a.valid:
		return -1
	case !b.valid:
		return 1
	}
	if c := compareInts(a.nums[:], b.nums[:]); c != 0 {
		return c
	}
	return comparePre(a.pre, b.pre)
}

func (Semver) Compare(a, b string) int { return compareSemverValues(parseSemver(a), parseSemver(b)) }

func (Semver) IsPrerelease(v string) bool {
	parsed := parseSemver(v)
	return parsed.valid && len(parsed.pre) > 0
}

// semverComparator — одно элементарное условие: оператор и версия. any — «*»,
// подходит любая версия.
type semverComparator struct {
	op  string
	val semverValue
	any bool
}

func (c semverComparator) matches(v semverValue) bool {
	if c.any {
		return true
	}
	cmp := compareSemverValues(v, c.val)
	switch c.op {
	case "=":
		return cmp == 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	}
	return false
}

// parseSemverRange разбирает диапазон npm в дизъюнкцию конъюнкций: «||»
// разделяет альтернативы, пробелы внутри альтернативы — «и».
func parseSemverRange(constraint string) ([][]semverComparator, error) {
	text := strings.TrimSpace(constraint)
	if text == "" || text == "*" || text == "x" || text == "X" || text == "latest" {
		return [][]semverComparator{{{any: true}}}, nil
	}
	var out [][]semverComparator
	for _, alternative := range strings.Split(text, "||") {
		set, err := parseSemverSet(alternative)
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, nil
}

// semverLooseOp — оператор, отделённый от версии пробелом: «>= 0.3.0». npm
// такое принимает, и в реальных package.json это встречается тысячами
// (проверено на пакетах npm: 9000 таких требований из 7285 уникальных).
var semverLooseOp = regexp.MustCompile(`([<>]=?|=|\^|~>?)\s+`)

func parseSemverSet(text string) ([]semverComparator, error) {
	fields := strings.Fields(semverLooseOp.ReplaceAllString(strings.TrimSpace(text), "$1"))
	if len(fields) == 0 {
		return []semverComparator{{any: true}}, nil
	}
	// Дефисный диапазон «1.2.3 - 2.3.4» — единственная форма, где пробелы не
	// означают «и», поэтому разбирается до общего цикла.
	if len(fields) == 3 && fields[1] == "-" {
		low, err := partialLowerBound(fields[0])
		if err != nil {
			return nil, err
		}
		high, err := partialUpperBound(fields[2])
		if err != nil {
			return nil, err
		}
		return append(low, high...), nil
	}

	var set []semverComparator
	for _, field := range fields {
		comparators, err := parseSemverComparator(field)
		if err != nil {
			return nil, err
		}
		set = append(set, comparators...)
	}
	return set, nil
}

func parseSemverComparator(field string) ([]semverComparator, error) {
	text := strings.TrimSpace(field)
	if text == "" || text == "*" || text == "x" || text == "X" {
		return []semverComparator{{any: true}}, nil
	}
	switch {
	case strings.HasPrefix(text, "^"):
		return caretRange(text[1:])
	case strings.HasPrefix(text, "~>"):
		return tildeRange(text[2:])
	case strings.HasPrefix(text, "~"):
		return tildeRange(text[1:])
	case strings.HasPrefix(text, ">="):
		return boundComparator(">=", text[2:])
	case strings.HasPrefix(text, "<="):
		return boundComparator("<=", text[2:])
	case strings.HasPrefix(text, ">"):
		return boundComparator(">", text[1:])
	case strings.HasPrefix(text, "<"):
		return boundComparator("<", text[1:])
	case strings.HasPrefix(text, "="):
		text = strings.TrimSpace(text[1:])
	}
	// Без оператора: точная версия либо частичная («1.2», «1.2.x»).
	if isPartialSemver(text) {
		low, err := partialLowerBound(text)
		if err != nil {
			return nil, err
		}
		high, err := partialUpperBound(text)
		if err != nil {
			return nil, err
		}
		return append(low, high...), nil
	}
	parsed := parseSemver(text)
	if !parsed.valid {
		return nil, fmt.Errorf("%w: «%s» не является версией semver", ErrBadConstraint, field)
	}
	return []semverComparator{{op: "=", val: parsed}}, nil
}

func boundComparator(op, raw string) ([]semverComparator, error) {
	text := strings.TrimSpace(raw)
	if isPartialSemver(text) {
		// «>=1.2» — это «>=1.2.0», а «<1.2» — «<1.2.0»: нижняя и верхняя
		// границы у частичной версии разные, поэтому оператор учитывается.
		switch op {
		case ">=", "<":
			nums, pre, err := partialNums(text)
			if err != nil {
				return nil, err
			}
			return []semverComparator{{op: op, val: semverValue{nums: nums, pre: pre, valid: true}}}, nil
		case ">":
			return partialUpperOpen(text)
		case "<=":
			return partialUpperBound(text)
		}
	}
	parsed := parseSemver(text)
	if !parsed.valid {
		return nil, fmt.Errorf("%w: «%s%s» не разобрано", ErrBadConstraint, op, raw)
	}
	return []semverComparator{{op: op, val: parsed}}, nil
}

// isPartialSemver — версия задана не полностью: «1», «1.2», «1.2.x».
func isPartialSemver(text string) bool {
	if text == "" {
		return false
	}
	core, _, _ := strings.Cut(text, "-")
	parts := strings.Split(core, ".")
	if len(parts) < 3 {
		return true
	}
	for _, part := range parts {
		if part == "x" || part == "X" || part == "*" {
			return true
		}
	}
	return false
}

// partialNums — числовая часть частичной версии, недостающие позиции нулями.
func partialNums(text string) ([3]int, []string, error) {
	var nums [3]int
	core, pre, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(text), "v"), "-")
	if idx := strings.IndexByte(core, '+'); idx >= 0 {
		core = core[:idx]
	}
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return nums, nil, fmt.Errorf("%w: «%s» — больше трёх сегментов", ErrBadConstraint, text)
	}
	for i, part := range parts {
		if part == "x" || part == "X" || part == "*" || part == "" {
			break
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nums, nil, fmt.Errorf("%w: «%s» не является версией", ErrBadConstraint, text)
		}
		nums[i] = n
	}
	var preParts []string
	if pre != "" {
		preParts = strings.Split(pre, ".")
	}
	return nums, preParts, nil
}

// definedLevels — сколько сегментов задано явно: «1» → 1, «1.2» → 2,
// «1.2.x» → 2, «1.2.3» → 3.
func definedLevels(text string) int {
	core, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(text), "v"), "-")
	parts := strings.Split(core, ".")
	level := 0
	for _, part := range parts {
		if part == "x" || part == "X" || part == "*" || part == "" {
			break
		}
		level++
	}
	if level > 3 {
		level = 3
	}
	return level
}

func partialLowerBound(text string) ([]semverComparator, error) {
	if definedLevels(text) == 0 {
		return []semverComparator{{any: true}}, nil
	}
	nums, pre, err := partialNums(text)
	if err != nil {
		return nil, err
	}
	return []semverComparator{{op: ">=", val: semverValue{nums: nums, pre: pre, valid: true}}}, nil
}

// partialUpperBound — верхняя граница включающего диапазона: «1.2» значит
// «всё в пределах 1.2», то есть «<1.3.0».
func partialUpperBound(text string) ([]semverComparator, error) {
	level := definedLevels(text)
	if level == 0 {
		return []semverComparator{{any: true}}, nil
	}
	nums, pre, err := partialNums(text)
	if err != nil {
		return nil, err
	}
	if level == 3 {
		return []semverComparator{{op: "<=", val: semverValue{nums: nums, pre: pre, valid: true}}}, nil
	}
	return []semverComparator{{op: "<", val: bumpLevel(nums, level)}}, nil
}

// partialUpperOpen — «>1.2» значит «строго выше всего, что входит в 1.2»,
// то есть «>=1.3.0».
func partialUpperOpen(text string) ([]semverComparator, error) {
	level := definedLevels(text)
	if level == 0 {
		return []semverComparator{{any: true}}, nil
	}
	nums, _, err := partialNums(text)
	if err != nil {
		return nil, err
	}
	if level == 3 {
		return []semverComparator{{op: ">", val: semverValue{nums: nums, valid: true}}}, nil
	}
	return []semverComparator{{op: ">=", val: bumpLevel(nums, level)}}, nil
}

func bumpLevel(nums [3]int, level int) semverValue {
	out := semverValue{nums: nums, valid: true}
	out.nums[level-1]++
	for i := level; i < 3; i++ {
		out.nums[i] = 0
	}
	return out
}

// caretRange — «^1.2.3»: совместимо по старшему ненулевому сегменту.
func caretRange(raw string) ([]semverComparator, error) {
	text := strings.TrimSpace(raw)
	level := definedLevels(text)
	if level == 0 {
		return []semverComparator{{any: true}}, nil
	}
	nums, pre, err := partialNums(text)
	if err != nil {
		return nil, err
	}
	low := semverComparator{op: ">=", val: semverValue{nums: nums, pre: pre, valid: true}}

	// Поднимается старший НЕнулевой из заданных сегментов: ^1.2.3 → <2.0.0,
	// ^0.2.3 → <0.3.0, ^0.0.3 → <0.0.4. Так задумано в npm: нулевой мажор не
	// даёт обещаний совместимости, и каждый следующий ноль сужает диапазон.
	// Если все заданные сегменты нулевые (^0, ^0.0), поднимается последний.
	bump := level
	for i := 0; i < level; i++ {
		if nums[i] != 0 {
			bump = i + 1
			break
		}
	}
	return []semverComparator{low, {op: "<", val: bumpLevel(nums, bump)}}, nil
}

// tildeRange — «~1.2.3»: допускается рост последнего заданного сегмента,
// но не того, что выше.
func tildeRange(raw string) ([]semverComparator, error) {
	text := strings.TrimSpace(raw)
	level := definedLevels(text)
	if level == 0 {
		return []semverComparator{{any: true}}, nil
	}
	nums, pre, err := partialNums(text)
	if err != nil {
		return nil, err
	}
	low := semverComparator{op: ">=", val: semverValue{nums: nums, pre: pre, valid: true}}
	bump := 2
	if level == 1 {
		bump = 1
	}
	return []semverComparator{low, {op: "<", val: bumpLevel(nums, bump)}}, nil
}

func (s Semver) Satisfies(constraint, v string) (bool, error) {
	return s.satisfies(constraint, v, false)
}

// satisfies с allowPre=true снимает правило npm про пререлизы. Нужно только
// для запасного захода в Select: у пакета может не быть ни одного релиза.
func (s Semver) satisfies(constraint, v string, allowPre bool) (bool, error) {
	parsed := parseSemver(v)
	if !parsed.valid {
		return false, nil
	}
	sets, err := parseSemverRange(constraint)
	if err != nil {
		return false, err
	}
	for _, set := range sets {
		if semverSetMatches(set, parsed, allowPre) {
			return true, nil
		}
	}
	return false, nil
}

// semverSetMatches — конъюнкция условий с правилом npm про пререлизы:
// 2.0.0-rc1 подходит только там, где пререлиз назван явно и у того же
// мажора-минора-патча. Иначе «^1.0.0» затягивал бы 2.0.0-rc1 через
// нижнюю границу.
func semverSetMatches(set []semverComparator, v semverValue, allowPre bool) bool {
	for _, c := range set {
		if !c.matches(v) {
			return false
		}
	}
	if len(v.pre) == 0 || allowPre {
		return true
	}
	for _, c := range set {
		if c.any || len(c.val.pre) == 0 {
			continue
		}
		if c.val.nums == v.nums {
			return true
		}
	}
	return false
}

func (s Semver) Select(constraint string, available []string) (string, error) {
	allowPre := strings.Contains(constraint, "-")
	match := func(v string) (bool, error) { return s.satisfies(constraint, v, allowPre) }
	selected, err := selectHighest(s, match, available, allowPre)
	if err == nil || allowPre {
		return selected, err
	}
	// Требование стабильной версии не выполнилось: у пакета может не быть
	// ни одного релиза, только пререлизы. Второй заход с ними — чтобы
	// зависимость не потерялась молча.
	loose := func(v string) (bool, error) { return s.satisfies(constraint, v, true) }
	return selectHighest(s, loose, available, true)
}
