package depfile

import (
	"encoding/json"
	"regexp"
	"strings"
)

func parseJS(base string, content []byte) ([]RawDependency, error) {
	switch base {
	case "package-lock.json":
		return parsePackageLock(content)
	case "yarn.lock":
		return parseYarnLock(content)
	case "package.json":
		return parsePackageJSON(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для npm. Поддерживаются: package-lock.json, yarn.lock, package.json",
		base)
}

var exactSemver = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// parsePackageLock — форматы v1, v2 и v3. Прямые зависимости берутся из
// корневой записи: без этого разделения весь lock-файл считался бы прямыми
// зависимостями, и заявка на пять пакетов превращалась бы в заявку на триста.
func parsePackageLock(content []byte) ([]RawDependency, error) {
	var data struct {
		Packages     map[string]lockPackage `json:"packages"`
		Dependencies map[string]lockV1Entry `json:"dependencies"`
		Direct       map[string]string      `json:"-"`
		Deps         map[string]string      `json:"devDependencies"`
		Prod         map[string]string      `json:"dependencies_"`
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, invalidf("Файл package-lock.json не является корректным JSON: %v", err)
	}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, invalidf("Файл package-lock.json не является корректным JSON: %v", err)
	}

	direct := map[string]bool{}
	if root, ok := data.Packages[""]; ok {
		for _, section := range []map[string]string{
			root.Dependencies, root.DevDependencies, root.OptionalDependencies,
		} {
			for name := range section {
				direct[name] = true
			}
		}
	} else {
		for _, key := range []string{"dependencies", "devDependencies"} {
			var section map[string]json.RawMessage
			if err := json.Unmarshal(raw[key], &section); err == nil {
				for name := range section {
					direct[name] = true
				}
			}
		}
	}

	var out []RawDependency
	if len(data.Packages) > 0 { // lockfileVersion 2/3
		for lockPath, meta := range data.Packages {
			if lockPath == "" || meta.Link {
				continue
			}
			name := meta.Name
			if name == "" {
				name = nameFromLockPath(lockPath)
			}
			if name == "" || meta.Version == "" {
				continue
			}
			out = append(out, kindFor(name, meta.Version, direct))
		}
	} else { // lockfileVersion 1
		walkLockV1(data.Dependencies, direct, &out)
	}
	return dedupe(out, nameVersionKey), nil
}

type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type lockV1Entry struct {
	Version      string                 `json:"version"`
	Dependencies map[string]lockV1Entry `json:"dependencies"`
}

func walkLockV1(tree map[string]lockV1Entry, direct map[string]bool, out *[]RawDependency) {
	for name, meta := range tree {
		if meta.Version != "" {
			*out = append(*out, kindFor(name, meta.Version, direct))
		}
		if len(meta.Dependencies) > 0 {
			walkLockV1(meta.Dependencies, direct, out)
		}
	}
}

func kindFor(name, version string, direct map[string]bool) RawDependency {
	if direct[name] {
		return RawDependency{Name: name, Version: version, Kind: KindDirect}
	}
	return transitive(name, version)
}

// nameFromLockPath — имя пакета из пути вида node_modules/@scope/pkg.
func nameFromLockPath(lockPath string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(lockPath, marker)
	if idx == -1 {
		return ""
	}
	return lockPath[idx+len(marker):]
}

// parseYarnLock — классический (v1) текстовый формат и YAML-подобный berry.
// Разбирается построчно, а не YAML-парсером: v1 не является YAML, и один
// разбор на оба формата проще, чем выбор парсера по догадке о версии.
func parseYarnLock(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	var currentNames []string

	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, " \t\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// Заголовок записи — без отступа и с двоеточием на конце.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") &&
			strings.HasSuffix(line, ":") {
			currentNames = yarnSpecNames(strings.TrimSuffix(line, ":"))
			continue
		}
		stripped := strings.TrimSpace(line)
		if !strings.HasPrefix(stripped, "version") || len(currentNames) == 0 {
			continue
		}
		var value string
		if idx := strings.Index(stripped, ":"); idx >= 0 {
			value = stripped[idx+1:]
		} else if parts := strings.SplitN(stripped, " ", 2); len(parts) == 2 {
			value = parts[1]
		}
		version := strings.Trim(strings.TrimSpace(value), `",`)
		for _, name := range currentNames {
			out = append(out, transitive(name, version))
		}
		currentNames = nil
	}
	if len(out) == 0 {
		return nil, invalidf("Не удалось разобрать yarn.lock: не найдено ни одной записи")
	}
	return dedupe(out, nameVersionKey), nil
}

// yarnSpecNames — имена из заголовка вида `"@scope/pkg@^1.0", other@~2.0:`.
func yarnSpecNames(header string) []string {
	var names []string
	for _, chunk := range strings.Split(header, ",") {
		spec := strings.Trim(strings.TrimSpace(chunk), `"`)
		if spec == "" {
			continue
		}
		scoped := strings.HasPrefix(spec, "@")
		body := spec
		if scoped {
			body = spec[1:]
		}
		name := strings.SplitN(body, "@", 2)[0]
		if name == "" {
			continue
		}
		if scoped {
			name = "@" + name
		}
		names = append(names, name)
	}
	return names
}

func parsePackageJSON(content []byte) ([]RawDependency, error) {
	var data struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, invalidf("Файл package.json не является корректным JSON: %v", err)
	}
	var out []RawDependency
	for _, section := range []map[string]string{
		data.Dependencies, data.DevDependencies, data.OptionalDependencies,
	} {
		for name, spec := range section {
			version := strings.TrimSpace(spec)
			if exactSemver.MatchString(version) {
				out = append(out, direct(name, version))
				continue
			}
			out = append(out, unpinned(name,
				"«"+name+"»: «"+version+"» — диапазон версий; укажите точную версию"))
		}
	}
	return out, nil
}
