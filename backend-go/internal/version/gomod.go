package version

import (
	"fmt"
	"strings"
)

// GoMod — правила go. Диапазонов здесь нет: go.mod требует конкретную версию
// (MVS выбирает максимум из требований ещё до нас), поэтому схема только
// сравнивает версии и проверяет точное совпадение.
//
// Псевдоверсии («v0.0.0-20221227161230-091c0ba34f0a») — валидный semver с
// пререлизом, и общий компаратор упорядочивает их правильно.
type GoMod struct{}

func (GoMod) Name() string { return "go" }

func (GoMod) Compare(a, b string) int {
	return compareSemverValues(parseSemver(strings.TrimSuffix(a, "+incompatible")),
		parseSemver(strings.TrimSuffix(b, "+incompatible")))
}

func (GoMod) IsPrerelease(v string) bool {
	parsed := parseSemver(strings.TrimSuffix(v, "+incompatible"))
	return parsed.valid && len(parsed.pre) > 0
}

func (GoMod) Satisfies(constraint, v string) (bool, error) {
	return strings.TrimSpace(constraint) == strings.TrimSpace(v), nil
}

// Select возвращает саму версию требования: выбирать не из чего, требование
// уже точное. Проверка по списку доступных — только чтобы отличить «версии
// нет в реестре» от «версия есть».
func (g GoMod) Select(constraint string, available []string) (string, error) {
	want := strings.TrimSpace(constraint)
	if want == "" {
		return "", fmt.Errorf("%w: пустая версия модуля", ErrBadConstraint)
	}
	if len(available) == 0 {
		return want, nil
	}
	for _, candidate := range available {
		if strings.TrimSpace(candidate) == want {
			return want, nil
		}
	}
	return "", ErrNoMatch
}
