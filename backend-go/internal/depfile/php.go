package depfile

import (
	"encoding/json"
	"regexp"
	"strings"
)

var exactComposerVersion = regexp.MustCompile(`^v?\d+(\.\d+){1,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

func parsePHP(base string, content []byte) ([]RawDependency, error) {
	if base != "composer.json" {
		return nil, invalidf("Файл «%s» пока не поддерживается для composer. Используйте composer.json", base)
	}
	var doc struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, invalidf("Файл composer.json не является корректным JSON: %v", err)
	}
	var out []RawDependency
	for _, section := range []map[string]string{doc.Require, doc.RequireDev} {
		for name, spec := range section {
			if name == "php" || strings.HasPrefix(name, "ext-") {
				continue
			}
			version := strings.TrimSpace(spec)
			if !exactComposerVersion.MatchString(version) {
				out = append(out, unpinned(name,
					"«"+name+"»: «"+version+"» — диапазон версий; укажите точную версию"))
				continue
			}
			out = append(out, direct(name, version))
		}
	}
	if len(out) == 0 {
		return nil, invalidf("В composer.json не найдено зависимостей")
	}
	return dedupe(out, lowerNameVersionKey), nil
}
