package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Terraform использует SemVer для версий provider'ов.
type Terraform struct{ Semver }

func (Terraform) Name() string { return "terraform" }

// Composer близок к SemVer, но допускает запятые как AND, одиночный | как
// OR, stability flags и оператор !=. Эти различия нормализуются здесь, а не
// в общем npm-парсере.
type Composer struct{ Semver }

func (Composer) Name() string { return "php" }

var composerStability = regexp.MustCompile(`@[A-Za-z]+\b`)

func normalizeComposerConstraint(value string) (string, []string, error) {
	text := strings.TrimSpace(composerStability.ReplaceAllString(value, ""))
	if text == "" || text == "*" {
		return "*", nil, nil
	}
	if strings.Contains(strings.ToLower(text), "dev-") || strings.Contains(text, "self.version") {
		return "", nil, fmt.Errorf("%w: динамическое требование Composer «%s»", ErrBadConstraint, value)
	}
	text = strings.ReplaceAll(text, ",", " ")
	// Composer принимает и |, и ||. Сначала защищаем ||, затем расширяем |.
	text = strings.ReplaceAll(text, "||", "\x00")
	text = strings.ReplaceAll(text, "|", "||")
	text = strings.ReplaceAll(text, "\x00", "||")
	var exclusions []string
	var kept []string
	for _, field := range strings.Fields(text) {
		if strings.HasPrefix(field, "!=") {
			exclusions = append(exclusions, strings.TrimPrefix(field, "!="))
			continue
		}
		kept = append(kept, field)
	}
	if len(kept) == 0 {
		kept = append(kept, "*")
	}
	return strings.Join(kept, " "), exclusions, nil
}

func (c Composer) Satisfies(constraint, candidate string) (bool, error) {
	normalized, exclusions, err := normalizeComposerConstraint(constraint)
	if err != nil {
		return false, err
	}
	ok, err := c.Semver.Satisfies(normalized, candidate)
	if err != nil || !ok {
		return ok, err
	}
	for _, excluded := range exclusions {
		matches, matchErr := c.Semver.Satisfies(excluded, candidate)
		if matchErr != nil {
			return false, matchErr
		}
		if matches {
			return false, nil
		}
	}
	return true, nil
}

func (c Composer) Select(constraint string, available []string) (string, error) {
	allowPre := strings.Contains(constraint, "-") || strings.Contains(constraint, "@dev")
	return selectHighest(c, func(candidate string) (bool, error) {
		return c.Satisfies(constraint, candidate)
	}, available, allowPre)
}

// LuaRocks сравнивает сначала upstream-версию, затем revision после
// последнего дефиса: 1.2.0-2 новее 1.2.0-1. Это не prerelease SemVer.
type LuaRocks struct{}

func (LuaRocks) Name() string { return "luarocks" }

func splitRockVersion(value string) (string, int) {
	text := strings.TrimSpace(value)
	idx := strings.LastIndex(text, "-")
	if idx < 0 {
		return text, 0
	}
	revision, err := strconv.Atoi(text[idx+1:])
	if err != nil {
		return text, 0
	}
	return text[:idx], revision
}

func (LuaRocks) Compare(a, b string) int {
	aBase, aRevision := splitRockVersion(a)
	bBase, bRevision := splitRockVersion(b)
	if compared := (Semver{}).Compare(aBase, bBase); compared != 0 {
		return compared
	}
	switch {
	case aRevision < bRevision:
		return -1
	case aRevision > bRevision:
		return 1
	default:
		return 0
	}
}

func (LuaRocks) IsPrerelease(value string) bool {
	base, _ := splitRockVersion(value)
	return (Semver{}).IsPrerelease(base)
}

func rockComparator(text string) (operator, wanted string) {
	text = strings.TrimSpace(text)
	for _, candidate := range []string{"~>", ">=", "<=", "~=", "!=", "==", ">", "<", "="} {
		if strings.HasPrefix(text, candidate) {
			return candidate, strings.TrimSpace(strings.TrimPrefix(text, candidate))
		}
	}
	return "=", text
}

func (l LuaRocks) Satisfies(constraint, candidate string) (bool, error) {
	text := strings.TrimSpace(constraint)
	if text == "" || text == "*" {
		return true, nil
	}
	// В rockspec ограничения обычно разделены запятыми. Разрешаем также
	// последовательность компараторов без запятой: >= 1.0 < 2.0.
	text = regexp.MustCompile(`\s+([<>~=!])`).ReplaceAllString(text, ",$1")
	for _, clause := range strings.Split(text, ",") {
		if strings.TrimSpace(clause) == "" {
			continue
		}
		op, wanted := rockComparator(clause)
		if wanted == "" {
			return false, fmt.Errorf("%w: пустое ограничение LuaRocks «%s»", ErrBadConstraint, constraint)
		}
		candidateBase, _ := splitRockVersion(candidate)
		wantedBase, _ := splitRockVersion(wanted)
		cmp := l.Compare(candidate, wanted)
		// Если revision в требовании не указан, сравнивается upstream-версия:
		// запись "1.0" должна принять опубликованный rock 1.0-3.
		if !strings.Contains(wanted, "-") {
			cmp = (Semver{}).Compare(candidateBase, wantedBase)
		}
		switch op {
		case "=", "==":
			if cmp != 0 {
				return false, nil
			}
		case "!=":
			if cmp == 0 {
				return false, nil
			}
		case ">":
			if cmp <= 0 {
				return false, nil
			}
		case ">=":
			if cmp < 0 {
				return false, nil
			}
		case "<":
			if cmp >= 0 {
				return false, nil
			}
		case "<=":
			if cmp > 0 {
				return false, nil
			}
		case "~>", "~=":
			if cmp < 0 {
				return false, nil
			}
			parts := strings.Split(wantedBase, ".")
			upper := wantedBase
			if len(parts) > 1 {
				minor, err := strconv.Atoi(parts[len(parts)-2])
				if err != nil {
					return false, fmt.Errorf("%w: версия LuaRocks «%s»", ErrBadConstraint, wanted)
				}
				parts[len(parts)-2] = strconv.Itoa(minor + 1)
				parts[len(parts)-1] = "0"
				upper = strings.Join(parts, ".")
			}
			if (Semver{}).Compare(candidateBase, upper) >= 0 {
				return false, nil
			}
		default:
			return false, fmt.Errorf("%w: оператор LuaRocks «%s»", ErrBadConstraint, op)
		}
	}
	return true, nil
}

func (l LuaRocks) Select(constraint string, available []string) (string, error) {
	return selectHighest(l, func(candidate string) (bool, error) {
		return l.Satisfies(constraint, candidate)
	}, available, strings.Contains(constraint, "-"))
}

// Maven реализует интервалы Maven ([1,2), (,1], [1]) и точные версии.
// Сравнение qualifier'ов следует порядку Maven для распространённых значений;
// неизвестные qualifier'ы сравниваются лексикографически.
type Maven struct{}

func (Maven) Name() string { return "maven" }

var mavenTokenRE = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

func mavenTokens(value string) []string {
	return mavenTokenRE.FindAllString(strings.ToLower(strings.TrimSpace(value)), -1)
}

var mavenQualifierRank = map[string]int{
	"alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3,
	"rc": -2, "cr": -2, "snapshot": -1, "": 0, "final": 0, "ga": 0,
	"release": 0, "sp": 1,
}

func compareMavenToken(left, right string) int {
	leftNumber, leftErr := strconv.Atoi(left)
	rightNumber, rightErr := strconv.Atoi(right)
	if leftErr == nil && rightErr == nil {
		switch {
		case leftNumber < rightNumber:
			return -1
		case leftNumber > rightNumber:
			return 1
		default:
			return 0
		}
	}
	if leftErr == nil {
		return 1
	}
	if rightErr == nil {
		return -1
	}
	leftRank, leftKnown := mavenQualifierRank[left]
	rightRank, rightKnown := mavenQualifierRank[right]
	if leftKnown || rightKnown {
		if !leftKnown {
			leftRank = 0
		}
		if !rightKnown {
			rightRank = 0
		}
		if leftRank < rightRank {
			return -1
		}
		if leftRank > rightRank {
			return 1
		}
	}
	return strings.Compare(left, right)
}

func (Maven) Compare(a, b string) int {
	left, right := mavenTokens(a), mavenTokens(b)
	count := len(left)
	if len(right) > count {
		count = len(right)
	}
	for idx := 0; idx < count; idx++ {
		l, r := "0", "0"
		if idx < len(left) {
			l = left[idx]
		}
		if idx < len(right) {
			r = right[idx]
		}
		if compared := compareMavenToken(l, r); compared != 0 {
			return compared
		}
	}
	return 0
}

func (Maven) IsPrerelease(value string) bool {
	for _, token := range mavenTokens(value) {
		if rank, ok := mavenQualifierRank[token]; ok && rank < 0 {
			return true
		}
	}
	return false
}

func splitMavenIntervals(text string) []string {
	var out []string
	start := -1
	for idx, char := range text {
		if (char == '[' || char == '(') && start < 0 {
			start = idx
		}
		if (char == ']' || char == ')') && start >= 0 {
			out = append(out, strings.TrimSpace(text[start:idx+1]))
			start = -1
		}
	}
	return out
}

func (m Maven) intervalMatches(interval, candidate string) (bool, error) {
	if len(interval) < 2 {
		return false, fmt.Errorf("%w: интервал Maven «%s»", ErrBadConstraint, interval)
	}
	inner := strings.TrimSpace(interval[1 : len(interval)-1])
	if !strings.Contains(inner, ",") {
		return candidate == inner, nil
	}
	low, high, _ := strings.Cut(inner, ",")
	low, high = strings.TrimSpace(low), strings.TrimSpace(high)
	if low != "" {
		cmp := m.Compare(candidate, low)
		if cmp < 0 || (cmp == 0 && interval[0] == '(') {
			return false, nil
		}
	}
	if high != "" {
		cmp := m.Compare(candidate, high)
		if cmp > 0 || (cmp == 0 && interval[len(interval)-1] == ')') {
			return false, nil
		}
	}
	return true, nil
}

func (m Maven) Satisfies(constraint, candidate string) (bool, error) {
	text := strings.TrimSpace(constraint)
	if text == "" || text == "*" {
		return true, nil
	}
	if strings.Contains(text, "${") || strings.HasPrefix(text, "<не удалось") {
		return false, fmt.Errorf("%w: %s", ErrBadConstraint, text)
	}
	if text[0] != '[' && text[0] != '(' {
		return candidate == text, nil
	}
	intervals := splitMavenIntervals(text)
	if len(intervals) == 0 {
		return false, fmt.Errorf("%w: интервал Maven «%s»", ErrBadConstraint, constraint)
	}
	for _, interval := range intervals {
		ok, err := m.intervalMatches(interval, candidate)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (m Maven) Select(constraint string, available []string) (string, error) {
	return selectHighest(m, func(candidate string) (bool, error) {
		return m.Satisfies(constraint, candidate)
	}, available, strings.IndexFunc(constraint, unicode.IsLetter) >= 0)
}
