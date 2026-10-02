package depfile

import (
	"encoding/xml"
	"regexp"
	"strings"
)

func parseMaven(base string, content []byte) ([]RawDependency, error) {
	switch base {
	case "pom.xml":
		return parseMavenPOM(content)
	case "build.gradle", "build.gradle.kts":
		return parseGradleDependencies(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для maven. Поддерживаются: pom.xml, build.gradle, build.gradle.kts",
		base)
}

func parseMavenPOM(content []byte) ([]RawDependency, error) {
	var project struct {
		Dependencies []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"dependencies>dependency"`
	}
	if err := xml.Unmarshal(content, &project); err != nil {
		return nil, invalidf("Файл pom.xml не является корректным XML: %v", err)
	}
	var out []RawDependency
	for _, dep := range project.Dependencies {
		name := strings.TrimSpace(dep.GroupID) + ":" + strings.TrimSpace(dep.ArtifactID)
		version := strings.TrimSpace(dep.Version)
		if strings.Trim(name, ":") == "" {
			continue
		}
		if version == "" || strings.Contains(version, "${") {
			out = append(out, unpinned(name,
				"Для «"+name+"» в pom.xml не указана точная версия"))
			continue
		}
		out = append(out, direct(name, version))
	}
	if len(out) == 0 {
		return nil, invalidf("В pom.xml не найдено зависимостей")
	}
	return dedupe(out, nameVersionKey), nil
}

var gradleDependency = regexp.MustCompile(`(?m)(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt)\s*(\(\s*)?["']([^:"']+):([^:"']+):([^"']+)["']`)

func parseGradleDependencies(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, match := range gradleDependency.FindAllSubmatch(content, -1) {
		name := strings.TrimSpace(string(match[3])) + ":" + strings.TrimSpace(string(match[4]))
		version := strings.TrimSpace(string(match[5]))
		if version == "" || strings.Contains(version, "$") {
			out = append(out, unpinned(name,
				"Для «"+name+"» в Gradle не указана точная версия"))
			continue
		}
		out = append(out, direct(name, version))
	}
	if len(out) == 0 {
		return nil, invalidf("В файле Gradle не найдено зависимостей с координатами group:artifact:version")
	}
	return dedupe(out, nameVersionKey), nil
}
