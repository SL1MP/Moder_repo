package depfile

import (
	"encoding/json"
	"regexp"
	"strings"
)

func parseConan(base string, content []byte) ([]RawDependency, error) {
	switch base {
	case "conanfile.txt":
		return parseConanFileTXT(content)
	case "conanfile.py":
		return parseConanFilePY(content)
	case "conan.lock":
		return parseConanLock(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для conan. Поддерживаются: conanfile.txt, conanfile.py, conan.lock",
		base)
}

func parseConanFileTXT(content []byte) ([]RawDependency, error) {
	if !strings.Contains(string(content), "[") {
		return parseConanCoordinates(content)
	}
	inRequires := false
	var out []RawDependency
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inRequires = strings.EqualFold(line, "[requires]")
			continue
		}
		if !inRequires || line == "" {
			continue
		}
		ref := strings.SplitN(line, "@", 2)[0]
		parts := strings.Split(ref, "/")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, invalidf("Не удалось разобрать зависимость conan: «%s»", line)
		}
		out = append(out, direct(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])))
	}
	if len(out) == 0 {
		return nil, invalidf("В conanfile.txt не найдено зависимостей в секции [requires]")
	}
	return dedupe(out, lowerNameVersionKey), nil
}

// parseConanCoordinates — сокращённый вид name/version, по одной записи на
// строку. Допускает recipe revision и user/channel, но в заявку передаёт
// только имя и версию: их же принимает плагин общего Conan-канала.
func parseConanCoordinates(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, line := range compactLines(content) {
		ref := strings.SplitN(line, "#", 2)[0]
		ref = strings.SplitN(ref, "@", 2)[0]
		parts := strings.Split(ref, "/")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, invalidf(
				"Не удалось разобрать строку conanfile.txt: «%s». Ожидается name/version",
				line)
		}
		out = append(out, direct(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])))
	}
	if len(out) == 0 {
		return nil, invalidf("В conanfile.txt не найдено зависимостей")
	}
	return dedupe(out, lowerNameVersionKey), nil
}

var conanPythonRequire = regexp.MustCompile(`(self\.)?requires\s*\(\s*["']([^/"']+)/([^@"']+)(@[^"']+)?["']`)

func parseConanFilePY(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, match := range conanPythonRequire.FindAllSubmatch(content, -1) {
		out = append(out, direct(string(match[2]), string(match[3])))
	}
	if len(out) == 0 {
		return nil, invalidf("В conanfile.py не найдено вызовов self.requires(\"name/version\")")
	}
	return dedupe(out, lowerNameVersionKey), nil
}

var conanLockedRef = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_+.-]*)/([A-Za-z0-9][A-Za-z0-9_+.-]*)(@[^#]+)?(#.*)?$`)

func parseConanLock(content []byte) ([]RawDependency, error) {
	var doc any
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, invalidf("Файл conan.lock не является корректным JSON: %v", err)
	}
	var out []RawDependency
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case string:
			match := conanLockedRef.FindStringSubmatch(strings.TrimSpace(typed))
			if match != nil {
				out = append(out, direct(match[1], match[2]))
			}
		}
	}
	walk(doc)
	if len(out) == 0 {
		return nil, invalidf("В conan.lock не найдено закреплённых ссылок name/version")
	}
	return dedupe(out, lowerNameVersionKey), nil
}
