package version

import (
	"fmt"
	"strconv"
	"strings"
)

// NuGet — правила nuget: версии до четырёх числовых сегментов с пререлизом и
// диапазоны в интервальной нотации («[1.0,2.0)», «1.0», «[1.0]»).
type NuGet struct{}

func (NuGet) Name() string { return "nuget" }

type nugetValue struct {
	nums  [4]int
	pre   []string
	valid bool
}

func parseNuGet(v string) nugetValue {
	s := strings.TrimSpace(v)
	if s == "" {
		return nugetValue{}
	}
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 4 {
		return nugetValue{}
	}
	out := nugetValue{valid: true}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nugetValue{}
		}
		out.nums[i] = n
	}
	if pre != "" {
		out.pre = strings.Split(strings.ToLower(pre), ".")
	}
	return out
}

func compareNuGetValues(a, b nugetValue) int {
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

func (NuGet) Compare(a, b string) int { return compareNuGetValues(parseNuGet(a), parseNuGet(b)) }

func (NuGet) IsPrerelease(v string) bool {
	parsed := parseNuGet(v)
	return parsed.valid && len(parsed.pre) > 0
}

// nugetRange — разобранный интервал. Пустая граница означает «не ограничено».
type nugetRange struct {
	min          nugetValue
	max          nugetValue
	hasMin       bool
	hasMax       bool
	minInclusive bool
	maxInclusive bool
	any          bool
}

// parseNuGetRange разбирает нотацию NuGet. Голая версия — это НЕ равенство, а
// «не ниже»: в nuspec «1.0» означает минимальную версию, и трактовать её как
// «ровно 1.0» значит терять зависимость там, где реестр отдал только 1.0.1.
func parseNuGetRange(constraint string) (nugetRange, error) {
	text := strings.TrimSpace(constraint)
	if text == "" || text == "*" {
		return nugetRange{any: true}, nil
	}
	open := text[0] == '[' || text[0] == '('
	if !open {
		parsed := parseNuGet(text)
		if !parsed.valid {
			return nugetRange{}, fmt.Errorf("%w: «%s» не является версией nuget", ErrBadConstraint, constraint)
		}
		return nugetRange{min: parsed, hasMin: true, minInclusive: true}, nil
	}
	last := text[len(text)-1]
	if last != ']' && last != ')' {
		return nugetRange{}, fmt.Errorf("%w: интервал «%s» не закрыт", ErrBadConstraint, constraint)
	}
	out := nugetRange{minInclusive: text[0] == '[', maxInclusive: last == ']'}
	inner := strings.TrimSpace(text[1 : len(text)-1])
	lowText, highText, hasComma := strings.Cut(inner, ",")
	lowText, highText = strings.TrimSpace(lowText), strings.TrimSpace(highText)
	if !hasComma {
		// «[1.0]» — ровно эта версия.
		parsed := parseNuGet(lowText)
		if !parsed.valid {
			return nugetRange{}, fmt.Errorf("%w: «%s» не является версией nuget", ErrBadConstraint, constraint)
		}
		return nugetRange{min: parsed, max: parsed, hasMin: true, hasMax: true,
			minInclusive: true, maxInclusive: true}, nil
	}
	if lowText != "" {
		parsed := parseNuGet(lowText)
		if !parsed.valid {
			return nugetRange{}, fmt.Errorf("%w: «%s» не является версией nuget", ErrBadConstraint, lowText)
		}
		out.min, out.hasMin = parsed, true
	}
	if highText != "" {
		parsed := parseNuGet(highText)
		if !parsed.valid {
			return nugetRange{}, fmt.Errorf("%w: «%s» не является версией nuget", ErrBadConstraint, highText)
		}
		out.max, out.hasMax = parsed, true
	}
	if !out.hasMin && !out.hasMax {
		out.any = true
	}
	return out, nil
}

func (r nugetRange) matches(v nugetValue) bool {
	if r.any {
		return true
	}
	if r.hasMin {
		cmp := compareNuGetValues(v, r.min)
		if cmp < 0 || (cmp == 0 && !r.minInclusive) {
			return false
		}
	}
	if r.hasMax {
		cmp := compareNuGetValues(v, r.max)
		if cmp > 0 || (cmp == 0 && !r.maxInclusive) {
			return false
		}
	}
	return true
}

func (n NuGet) Satisfies(constraint, v string) (bool, error) {
	parsed := parseNuGet(v)
	if !parsed.valid {
		return false, nil
	}
	rng, err := parseNuGetRange(constraint)
	if err != nil {
		return false, err
	}
	return rng.matches(parsed), nil
}

// Select — минимальная подходящая версия: так резолвит сам NuGet («lowest
// applicable version»), и брать максимальную значило бы отправлять на
// модерацию не то, что соберётся у разработчика.
func (n NuGet) Select(constraint string, available []string) (string, error) {
	rng, err := parseNuGetRange(constraint)
	if err != nil {
		return "", err
	}
	match := func(v string) (bool, error) { return n.Satisfies(constraint, v) }
	allowPre := (rng.hasMin && len(rng.min.pre) > 0) || (rng.hasMax && len(rng.max.pre) > 0)
	selected, err := selectLowest(n, match, available, allowPre)
	if err == nil || allowPre {
		return selected, err
	}
	return selectLowest(n, match, available, true)
}
