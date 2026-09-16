package depfile

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"regexp"
	"strings"
)

func parseDotNet(base string, content []byte) ([]RawDependency, error) {
	switch {
	case base == "packages.lock.json":
		return parsePackagesLockJSON(content)
	case base == "packages.config":
		return parsePackagesConfig(content)
	case strings.HasSuffix(strings.ToLower(base), ".csproj"):
		return parseCsproj(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для nuget. Поддерживаются: packages.lock.json, packages.config, *.csproj",
		base)
}

var exactNuGetVersion = regexp.MustCompile(`^\d+(\.\d+){0,3}(-[0-9A-Za-z.\-]+)?$`)

// parsePackagesLockJSON — поле type: Direct | Transitive | Project.
// Project пропускается: это ссылка на соседний проект решения, а не пакет.
func parsePackagesLockJSON(content []byte) ([]RawDependency, error) {
	var data struct {
		Dependencies map[string]map[string]struct {
			Type      string `json:"type"`
			Resolved  string `json:"resolved"`
			Requested string `json:"requested"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, invalidf("Файл packages.lock.json не является корректным JSON: %v", err)
	}
	var out []RawDependency
	for _, packages := range data.Dependencies {
		for name, meta := range packages {
			depType := strings.ToLower(meta.Type)
			if depType == "project" {
				continue
			}
			version := meta.Resolved
			if version == "" {
				version = meta.Requested
			}
			if version == "" {
				continue
			}
			kind := KindTransitive
			if depType == "direct" {
				kind = KindDirect
			}
			out = append(out, RawDependency{Name: name, Version: version, Kind: kind})
		}
	}
	if len(out) == 0 {
		return nil, invalidf("В packages.lock.json не найдено зависимостей")
	}
	return dedupe(out, lowerNameVersionKey), nil
}

// parsePackagesConfig — <package id="..." version="..." />.
func parsePackagesConfig(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	err := walkXML(content, "packages.config",
		func(tag string) bool { return tag == "package" },
		func(_ string, attrs map[string]string, _ string) {
			if id, version := attrs["id"], attrs["version"]; id != "" && version != "" {
				out = append(out, direct(id, version))
			}
		})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, invalidf("В packages.config не найдено элементов <package>")
	}
	return out, nil
}

// parseCsproj — <PackageReference Include="..." Version="..." />, а также
// PackageVersion (Central Package Management) и PackageDownload.
func parseCsproj(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	err := walkXML(content, "*.csproj", isPackageElement,
		func(_ string, attrs map[string]string, childVersion string) {
			name := attrs["Include"]
			if name == "" {
				name = attrs["Update"]
			}
			if name == "" {
				return
			}
			version := attrs["Version"]
			if version == "" {
				version = childVersion
			}
			version = strings.TrimSpace(version)
			if version == "" {
				out = append(out, unpinned(name,
					"«"+name+"»: версия задана переменной или отсутствует; укажите её явно"))
				return
			}
			// $(Var) — подстановка MSBuild; диапазон [1.0,2.0) — не точная версия.
			trimmed := strings.Trim(version, "[]()")
			if strings.HasPrefix(version, "$(") || !exactNuGetVersion.MatchString(trimmed) {
				out = append(out, unpinned(name,
					"«"+name+"»: «"+version+"» — не точная версия; укажите её явно"))
				return
			}
			out = append(out, direct(name, trimmed))
		})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, invalidf("В файле проекта не найдено элементов <PackageReference>")
	}
	return out, nil
}

// isPackageElement — элементы csproj, объявляющие зависимость.
// PackageVersion — Central Package Management, PackageDownload — загрузка без
// ссылки на сборку; оба тоже тянут пакет из реестра.
func isPackageElement(tag string) bool {
	switch tag {
	case "PackageReference", "PackageVersion", "PackageDownload":
		return true
	}
	return false
}

// walkXML обходит элементы документа и зовёт visit на тех, чьё имя (без
// пространства имён) принял interesting: с атрибутами и текстом вложенного
// <Version>, если он есть.
//
// Обход потоковый: нужные элементы встречаются на любой глубине (ItemGroup
// внутри Choose внутри When), и описывать эту вложенность типами значило бы
// поддерживать её вечно.
//
// Проверка имени стоит ДО разбора элемента, и это не оптимизация: разбор
// поглощает элемент целиком вместе с содержимым, поэтому разбор ItemGroup
// съел бы все PackageReference внутри, и ни один из них не был бы посещён.
// Так и было в первой версии — поймано тестом на вложенном csproj.
func walkXML(content []byte, filename string, interesting func(tag string) bool,
	visit func(tag string, attrs map[string]string, childVersion string)) error {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	// Файл приходит от пользователя: внешние сущности не разворачиваем, чтобы
	// XML не мог прочитать файл с диска или сходить в сеть.
	decoder.Entity = map[string]string{}
	decoder.Strict = false

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return invalidf("Файл %s не является корректным XML: %v", filename, err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !interesting(start.Name.Local) {
			continue
		}
		attrs := make(map[string]string, len(start.Attr))
		for _, attr := range start.Attr {
			attrs[attr.Name.Local] = attr.Value
		}
		var inner struct {
			Version string `xml:"Version"`
		}
		childVersion := ""
		if err := decoder.DecodeElement(&inner, &start); err == nil {
			childVersion = strings.TrimSpace(inner.Version)
		}
		visit(start.Name.Local, attrs, childVersion)
	}
}
