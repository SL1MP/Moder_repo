// Package version — сравнение версий и разбор диапазонов по правилам каждой
// экосистемы. Нужен для раскрытия транзитивных зависимостей: реестр отдаёт
// требование диапазоном («^4.17.21», «>=2,<4», «[13.0.1, )»), а модерация
// работает только с точной версией — вердикт выносится по конкретному
// артефакту, а не по обещанию, которое завтра означает другой пакет.
//
// Почему своя реализация, а не библиотека: четыре экосистемы — четыре разных
// набора правил (semver, PEP 440, NuGet-интервалы, MVS у Go), и ни одна
// библиотека не закрывает все четыре. Границы реализованного описаны у каждой
// схемы честно: там, где правило упрощено, это сказано в комментарии, а не
// скрыто за «обычно работает».
package version

import (
	"errors"
	"fmt"
)

// ErrNoMatch — ни одна из доступных версий не подходит под требование. Это
// не сбой: так бывает у пакета, требования которого разошлись с реестром
// (версию удалили, требование ссылается на пререлиз). Модерация должна
// показать это пользователю как «не смогли определить версию», а не молча
// пропустить зависимость.
var ErrNoMatch = errors.New("подходящая версия не найдена")

// ErrBadConstraint — требование не разобралось. Тоже не сбой сервиса:
// экзотический синтаксис встречается, и назвать его пользователю честнее,
// чем угадать.
var ErrBadConstraint = errors.New("требование не разобрано")

// Scheme — правила версий одной экосистемы.
type Scheme interface {
	// Name — код схемы, он же код менеджера.
	Name() string
	// Compare сравнивает версии: -1, 0, 1. Неразобранная версия считается
	// меньше любой разобранной — иначе мусорная строка выигрывала бы выбор.
	Compare(a, b string) int
	// IsPrerelease — версия является пререлизом (1.0.0-rc1, 2.0b3).
	IsPrerelease(v string) bool
	// Satisfies — версия удовлетворяет требованию.
	Satisfies(constraint, v string) (bool, error)
	// Select выбирает версию из доступных. Политика выбора — часть схемы, а
	// не общее правило: npm и pip берут максимальную подходящую, NuGet —
	// минимальную (так резолвит сам NuGet), Go версию не выбирает вовсе.
	Select(constraint string, available []string) (string, error)
}

// For возвращает схему по коду менеджера.
func For(manager string) (Scheme, error) {
	switch manager {
	case "npm":
		return Semver{}, nil
	case "pypi":
		return PEP440{}, nil
	case "nuget":
		return NuGet{}, nil
	case "go":
		return GoMod{}, nil
	}
	return nil, fmt.Errorf("нет схемы версий для менеджера «%s»", manager)
}

// selectHighest — общий выбор для npm и pypi: максимальная подходящая версия,
// пререлизы в расчёт не идут, пока их не потребовало само требование.
//
// Почему пререлизы отсекаются: «>=2.0» в файле зависимостей означает «любая
// стабильная от 2.0», и подставить туда 3.0.0-rc1 значит отправить на
// модерацию то, что разработчик не просил и в сборку не попадёт.
func selectHighest(s Scheme, satisfies func(string) (bool, error), available []string, allowPre bool) (string, error) {
	best := ""
	for _, candidate := range available {
		if !allowPre && s.IsPrerelease(candidate) {
			continue
		}
		ok, err := satisfies(candidate)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		if best == "" || s.Compare(candidate, best) > 0 {
			best = candidate
		}
	}
	if best == "" {
		return "", ErrNoMatch
	}
	return best, nil
}

// selectLowest — выбор NuGet: минимальная подходящая версия.
func selectLowest(s Scheme, satisfies func(string) (bool, error), available []string, allowPre bool) (string, error) {
	best := ""
	for _, candidate := range available {
		if !allowPre && s.IsPrerelease(candidate) {
			continue
		}
		ok, err := satisfies(candidate)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		if best == "" || s.Compare(candidate, best) < 0 {
			best = candidate
		}
	}
	if best == "" {
		return "", ErrNoMatch
	}
	return best, nil
}

// compareInts сравнивает номерные срезы разной длины, добивая нулями:
// 1.2 и 1.2.0 — одна и та же версия во всех четырёх экосистемах.
func compareInts(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
