package depfile

import (
	"regexp"
	"strings"
)

var rockDependency = regexp.MustCompile(`["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9.]*-[0-9]+)["']`)

func parseLuaRocks(base string, content []byte) ([]RawDependency, error) {
	if !strings.HasSuffix(base, ".rockspec") {
		return nil, invalidf("Файл «%s» не является rockspec", base)
	}
	var out []RawDependency
	for _, match := range rockDependency.FindAllSubmatch(content, -1) {
		name := string(match[1])
		if strings.EqualFold(name, "lua") {
			continue
		}
		out = append(out, direct(name, string(match[2])))
	}
	if len(out) == 0 {
		return nil, invalidf("В rockspec не найдено зависимостей с точной версией и ревизией (`== X.Y.Z-N`)")
	}
	return dedupe(out, lowerNameVersionKey), nil
}
