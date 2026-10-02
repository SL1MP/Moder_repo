package depfile

import (
	"regexp"
	"strings"
)

var rockDependency = regexp.MustCompile(`["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9.]*-[0-9]+)["']`)
var compactRockVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.]*-[0-9]+$`)

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
		return parseLuaRocksCoordinates(content)
	}
	return dedupe(out, lowerNameVersionKey), nil
}

func parseLuaRocksCoordinates(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, line := range compactLines(content) {
		idx := strings.LastIndex(line, "@")
		if idx <= 0 || idx == len(line)-1 {
			return nil, invalidf(
				"Не удалось разобрать строку rockspec: «%s». Ожидается rock@version-revision",
				line)
		}
		name := strings.TrimSpace(line[:idx])
		version := strings.TrimSpace(line[idx+1:])
		if name == "" || !compactRockVersion.MatchString(version) {
			return nil, invalidf(
				"Не удалось разобрать строку rockspec: «%s». Версия должна включать ревизию X.Y.Z-N",
				line)
		}
		out = append(out, direct(name, version))
	}
	if len(out) == 0 {
		return nil, invalidf("В rockspec не найдено зависимостей с точной версией и ревизией")
	}
	return dedupe(out, lowerNameVersionKey), nil
}
