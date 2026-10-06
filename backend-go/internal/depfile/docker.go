package depfile

import (
	"strings"

	"gopkg.in/yaml.v3"
)

func parseDocker(base string, content []byte) ([]RawDependency, error) {
	switch base {
	case "Dockerfile":
		return parseDockerfile(content)
	case "docker-compose.yml", "docker-compose.yaml":
		return parseDockerCompose(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для docker. Поддерживаются: Dockerfile, docker-compose.yml, docker-compose.yaml",
		base)
}

func parseDockerfile(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, raw := range strings.Split(string(content), "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		idx := 1
		if strings.HasPrefix(fields[idx], "--platform=") {
			idx++
		}
		if idx >= len(fields) || strings.EqualFold(fields[idx], "scratch") {
			continue
		}
		name, version, ok := splitDockerDependency(fields[idx])
		if !ok {
			out = append(out, unpinned(fields[idx],
				"Docker-образ должен содержать точный тег, например alpine:3.20"))
			continue
		}
		out = append(out, direct(name, version))
	}
	if len(out) == 0 {
		return nil, invalidf("В Dockerfile не найдено ни одной инструкции FROM с образом")
	}
	return dedupe(out, lowerNameVersionKey), nil
}

func parseDockerCompose(content []byte) ([]RawDependency, error) {
	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, invalidf("Файл docker-compose не является корректным YAML: %v", err)
	}
	var out []RawDependency
	for service, spec := range doc.Services {
		image := strings.TrimSpace(spec.Image)
		if image == "" {
			continue // сервис с build не является внешним образом
		}
		if strings.Contains(image, "${") {
			out = append(out, unpinned(image,
				"Образ сервиса «"+service+"» задан переменной; укажите точный image:tag@index-digest"))
			continue
		}
		name, version, ok := splitDockerDependency(image)
		if !ok {
			out = append(out, unpinned(image,
				"Docker-образ сервиса «"+service+"» должен содержать точный тег"))
			continue
		}
		out = append(out, direct(name, version))
	}
	if len(out) == 0 {
		return nil, invalidf("В docker-compose не найдено ни одного сервиса с полем image")
	}
	return dedupe(out, lowerNameVersionKey), nil
}

func splitDockerDependency(ref string) (string, string, bool) {
	imageAndTag, digest, hasDigest := strings.Cut(strings.TrimSpace(ref), "@")
	colon := strings.LastIndex(imageAndTag, ":")
	slash := strings.LastIndex(imageAndTag, "/")
	if colon <= slash || colon == len(imageAndTag)-1 {
		return ref, "", false
	}
	name, version := imageAndTag[:colon], imageAndTag[colon+1:]
	if hasDigest {
		if digest == "" {
			return ref, "", false
		}
		version += "@" + digest
	}
	return name, version, true
}
