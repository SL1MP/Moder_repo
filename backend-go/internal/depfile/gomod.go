package depfile

import (
	"regexp"
	"strings"
)

func parseGo(base string, content []byte) ([]RawDependency, error) {
	switch base {
	case "go.mod":
		return parseGoMod(content)
	case "go.sum":
		return parseGoSum(content)
	}
	return nil, invalidf("Файл «%s» не поддерживается для go. Поддерживаются: go.mod, go.sum", base)
}

var requireLine = regexp.MustCompile(`^(\S+)\s+(v\S+)(.*)$`)

// parseGoMod — блоки require; комментарий `// indirect` помечает транзитивную.
func parseGoMod(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	inBlock := false
	foundModule := false

	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "module ") {
			foundModule = true
			continue
		}
		if strings.HasPrefix(line, "require") && strings.HasSuffix(line, "(") {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		payload := line
		switch {
		case strings.HasPrefix(line, "require "):
			payload = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		case !inBlock:
			continue
		}
		comment := ""
		if idx := strings.Index(payload, "//"); idx >= 0 {
			comment = payload[idx+2:]
			payload = strings.TrimSpace(payload[:idx])
		}
		m := requireLine.FindStringSubmatch(payload)
		if m == nil {
			continue
		}
		kind := KindDirect
		if strings.Contains(comment, "indirect") {
			kind = KindTransitive
		}
		out = append(out, RawDependency{Name: m[1], Version: m[2], Kind: kind})
	}

	if len(out) == 0 && !foundModule {
		return nil, invalidf("Файл не похож на go.mod: нет директив module/require")
	}
	return out, nil
}

// parseGoSum — полный граф модулей. Записи помечаются direct НАМЕРЕННО.
//
// Формат не хранит признак прямой зависимости, и пометка transitive была бы
// утверждением, которого из файла не следует. Последствие было тяжёлым:
// транзитивные записи отбрасываются у заявки без include_transitive, и раз в
// go.sum транзитивным помечалось всё — отбрасывался весь файл, а заявка
// получалась пустой. Снаружи это выглядело как «go.sum не поддерживается».
func parseGoSum(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(string(content), "\n") {
		parts := strings.Fields(rawLine)
		if len(parts) < 3 {
			continue
		}
		module := parts[0]
		version := strings.TrimSuffix(parts[1], "/go.mod")
		if !strings.HasPrefix(version, "v") {
			continue
		}
		key := module + "\x00" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, direct(module, version))
	}
	if len(out) == 0 {
		return nil, invalidf("Не удалось разобрать go.sum: не найдено ни одной записи")
	}
	return out, nil
}
