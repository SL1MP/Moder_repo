package version

import "strings"

// Conan — версия и диапазоны Conan. Числовые версии сравниваются как semver,
// диапазон `[>=1.2.11 <2]` использует те же элементарные компараторы. Точная
// версия может быть произвольной строкой (например, cci.20210118), поэтому
// для неё сохраняется буквальное сравнение.
type Conan struct{}

func (Conan) Name() string { return "conan" }

func (Conan) Compare(a, b string) int {
	left, right := parseSemver(a), parseSemver(b)
	if left.valid || right.valid {
		return compareSemverValues(left, right)
	}
	return strings.Compare(a, b)
}

func (Conan) IsPrerelease(v string) bool { return Semver{}.IsPrerelease(v) }

func (Conan) Satisfies(constraint, v string) (bool, error) {
	constraint = strings.TrimSpace(constraint)
	if strings.HasPrefix(constraint, "[") && strings.HasSuffix(constraint, "]") {
		constraint = strings.TrimSpace(constraint[1 : len(constraint)-1])
	}
	// Conan допускает произвольные точные версии, не только semver.
	if !strings.ContainsAny(constraint, " <>~=^|*xX") {
		return constraint == v, nil
	}
	return Semver{}.Satisfies(constraint, v)
}

func (c Conan) Select(constraint string, available []string) (string, error) {
	// Точную ссылку выбираем буквально — это работает и для cci.* версий.
	trimmed := strings.TrimSpace(constraint)
	if !strings.ContainsAny(trimmed, "[] <>~=^|*xX") {
		for _, candidate := range available {
			if candidate == trimmed {
				return candidate, nil
			}
		}
		return "", ErrNoMatch
	}
	allowPre := strings.Contains(trimmed, "-")
	return selectHighest(c, func(v string) (bool, error) { return c.Satisfies(trimmed, v) }, available, allowPre)
}
