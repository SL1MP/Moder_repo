package depfile

import "strings"

func parseDocker(base string, content []byte) ([]RawDependency, error) {
	if base != "Dockerfile" {
		return nil, invalidf("Файл «%s» пока не поддерживается для docker. Используйте Dockerfile", base)
	}
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
