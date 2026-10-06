package depfile

import (
	"encoding/json"
	"regexp"
	"strings"
)

var exactComposerVersion = regexp.MustCompile(`^v?\d+(\.\d+){1,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

type composerLockedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parsePHP(base string, content []byte) ([]RawDependency, error) {
	switch base {
	case "composer.json":
		return parseComposerJSON(content)
	case "composer.lock":
		return parseComposerLock(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для composer. Поддерживаются: composer.json, composer.lock", base)
}

func parseComposerJSON(content []byte) ([]RawDependency, error) {
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

// parseComposerLock читает оба массива закрытого графа. Формат не хранит
// признак «прямая зависимость», а загружается один файл без composer.json,
// поэтому записи помечаются direct: иначе заявка с выключенной галочкой
// транзитивных зависимостей получалась бы пустой, как раньше происходило с
// go.sum.
func parseComposerLock(content []byte) ([]RawDependency, error) {
	var doc struct {
		Packages    []composerLockedPackage `json:"packages"`
		PackagesDev []composerLockedPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, invalidf("Файл composer.lock не является корректным JSON: %v", err)
	}
	var out []RawDependency
	for _, packages := range [][]composerLockedPackage{doc.Packages, doc.PackagesDev} {
		for _, pkg := range packages {
			name := strings.TrimSpace(pkg.Name)
			version := strings.TrimSpace(pkg.Version)
			if name != "" && version != "" {
				out = append(out, direct(name, version))
			}
		}
	}
	if len(out) == 0 {
		return nil, invalidf("В composer.lock не найдено зависимостей")
	}
	return dedupe(out, lowerNameVersionKey), nil
}
