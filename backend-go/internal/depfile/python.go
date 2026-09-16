package depfile

import (
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

func parsePython(base string, content []byte) ([]RawDependency, error) {
	switch {
	case base == "poetry.lock":
		return parsePoetryLock(content)
	case base == "pyproject.toml":
		return parsePyprojectTOML(content)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return parseRequirementsTxt(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для pypi. Поддерживаются: requirements.txt, poetry.lock, pyproject.toml",
		base)
}

var (
	reqLine = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*([=<>!~]=?[^;#]*)?(?:;.*)?$`)
	pinSpec = regexp.MustCompile(`^==\s*([^\s,]+)$`)
)

// parseRequirementsTxt — только точные пины `name==version` можно заводить.
func parseRequirementsTxt(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		// Директивы (-r, -e, --hash) и ссылки — не записи пакетов.
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") ||
			strings.HasPrefix(line, "git+") {
			continue
		}
		line = strings.TrimSpace(strings.TrimRight(
			strings.TrimSpace(strings.SplitN(line, "--hash", 2)[0]), `\`))

		m := reqLine.FindStringSubmatch(line)
		if m == nil {
			return nil, invalidf("Не удалось разобрать строку requirements.txt: «%s»",
				strings.TrimSpace(rawLine))
		}
		name, spec := m[1], strings.TrimSpace(m[3])
		pin := pinSpec.FindStringSubmatch(spec)
		if pin == nil {
			out = append(out, unpinned(name,
				"«"+line+"» — версия не закреплена (`==`); укажите точную версию, "+
					"модерация выполняется для конкретной версии"))
			continue
		}
		out = append(out, direct(name, pin[1]))
	}
	return out, nil
}

// parsePoetryLock — весь набор помечается транзитивным: формат не различает
// прямые и транзитивные, а прямые перечислены в pyproject.toml.
func parsePoetryLock(content []byte) ([]RawDependency, error) {
	var doc struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, invalidf("Файл poetry.lock не является корректным TOML: %v", err)
	}
	var out []RawDependency
	for _, pkg := range doc.Package {
		if pkg.Name != "" && pkg.Version != "" {
			out = append(out, transitive(pkg.Name, pkg.Version))
		}
	}
	return out, nil
}

// parsePyprojectTOML — PEP 621 project.dependencies и tool.poetry.dependencies.
func parsePyprojectTOML(content []byte) ([]RawDependency, error) {
	var doc struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, invalidf("Файл pyproject.toml не является корректным TOML: %v", err)
	}

	var out []RawDependency
	appendSpec := func(spec string) error {
		parsed, err := parseRequirementsTxt([]byte(spec))
		if err != nil {
			return err
		}
		out = append(out, parsed...)
		return nil
	}
	for _, dep := range doc.Project.Dependencies {
		if err := appendSpec(dep); err != nil {
			return nil, err
		}
	}
	for _, deps := range doc.Project.OptionalDependencies {
		for _, dep := range deps {
			if err := appendSpec(dep); err != nil {
				return nil, err
			}
		}
	}

	for name, spec := range doc.Tool.Poetry.Dependencies {
		if strings.EqualFold(name, "python") {
			continue
		}
		if version := poetrySpecVersion(spec); version != "" {
			out = append(out, direct(name, version))
			continue
		}
		out = append(out, unpinned(name,
			"«"+name+"» в pyproject.toml задан диапазоном; укажите точную версию"))
	}
	return out, nil
}

// poetrySpecVersion — точная версия из строки или из объекта {version = "..."}.
// Пустая строка — версия задана диапазоном.
func poetrySpecVersion(spec any) string {
	var value string
	switch t := spec.(type) {
	case string:
		value = strings.TrimSpace(t)
	case map[string]any:
		if v, ok := t["version"].(string); ok {
			value = strings.TrimSpace(v)
		}
	}
	if value == "" {
		return ""
	}
	if value[0] >= '0' && value[0] <= '9' {
		return value // точная версия без операторов
	}
	if strings.HasPrefix(value, "==") {
		return strings.TrimSpace(value[2:])
	}
	return ""
}
