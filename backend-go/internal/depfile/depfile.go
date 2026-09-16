// Package depfile — разбор файлов зависимостей: requirements.txt, go.sum,
// package-lock.json и остальные. Порт backend/app/managers/parsers/.
//
// Что здесь важно понимать. Разбор НЕ раскрывает граф зависимостей: он читает
// то, что уже написано в файле. Lock-файлы (poetry.lock, package-lock.json,
// go.sum, packages.lock.json) содержат полный закрытый набор, потому что его
// туда положил сам менеджер пакетов; манифесты (pyproject.toml, package.json,
// *.csproj) — только прямые зависимости. Разрешение закрытия по манифесту —
// отдельная задача, здесь её нет.
//
// Запись без точной версии не отбрасывается молча: она возвращается с пустой
// Version и объяснением в Note. Модерация выносит вердикт по конкретной
// версии, а диапазон «^1.2.0» завтра означает другой пакет — но пользователь
// должен увидеть, что именно не взяли и почему.
package depfile

import (
	"fmt"
	"path"
	"strings"
)

// RawDependency — запись из файла до нормализации плагином менеджера.
type RawDependency struct {
	Name    string
	Version string
	// Kind — direct | transitive. Заявка без include_transitive оставляет
	// только direct.
	Kind string
	// Note — почему версию не удалось взять. Заполняется вместо Version.
	Note string
}

const (
	KindDirect     = "direct"
	KindTransitive = "transitive"
)

// InvalidFormatError — файл не разобрался. Отдельный тип: «файл кривой» —
// ошибка пользователя (422), а не сбой сервиса.
type InvalidFormatError struct{ Message string }

func (e *InvalidFormatError) Error() string { return e.Message }

func invalidf(format string, args ...any) error {
	return &InvalidFormatError{Message: fmt.Sprintf(format, args...)}
}

// Parse разбирает файл зависимостей менеджера. filename может быть путём —
// берётся только базовое имя.
func Parse(manager, filename string, content []byte) ([]RawDependency, error) {
	base := path.Base(strings.ReplaceAll(strings.TrimSpace(filename), `\`, "/"))
	switch manager {
	case "pypi":
		return parsePython(base, content)
	case "npm":
		return parseJS(base, content)
	case "go":
		return parseGo(base, content)
	case "nuget":
		return parseDotNet(base, content)
	}
	return nil, invalidf("менеджер %q не поддерживается", manager)
}

// dedupe — одна запись на (имя, версия); direct имеет приоритет над
// transitive. Ключ приводится к нижнему регистру там, где менеджер
// нечувствителен к регистру (nuget), — вызывающий передаёт нужный
// нормализатор.
func dedupe(deps []RawDependency, key func(RawDependency) string) []RawDependency {
	best := make(map[string]int, len(deps))
	out := make([]RawDependency, 0, len(deps))
	for _, dep := range deps {
		k := key(dep)
		idx, seen := best[k]
		if !seen {
			best[k] = len(out)
			out = append(out, dep)
			continue
		}
		if out[idx].Kind == KindTransitive && dep.Kind == KindDirect {
			out[idx] = dep
		}
	}
	return out
}

func nameVersionKey(d RawDependency) string      { return d.Name + "\x00" + d.Version }
func lowerNameVersionKey(d RawDependency) string { return strings.ToLower(d.Name) + "\x00" + d.Version }

func direct(name, version string) RawDependency {
	return RawDependency{Name: name, Version: version, Kind: KindDirect}
}

func transitive(name, version string) RawDependency {
	return RawDependency{Name: name, Version: version, Kind: KindTransitive}
}

func unpinned(name, note string) RawDependency {
	return RawDependency{Name: name, Kind: KindDirect, Note: note}
}
