package depfile

import (
	"regexp"
	"strings"
)

var terraformLockProvider = regexp.MustCompile(`(?s)provider\s+"registry\.terraform\.io/([^"/]+/[^"/]+)"\s*\{.*?version\s*=\s*"([^"]+)"`)
var compactTerraformVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(:[A-Za-z0-9]+_[A-Za-z0-9]+)?$`)

func parseTerraform(base string, content []byte) ([]RawDependency, error) {
	switch base {
	case ".terraform.lock.hcl":
		return parseTerraformLock(content)
	case "versions.tf", "providers.tf":
		return parseTerraformConfig(content)
	}
	return nil, invalidf(
		"Файл «%s» не поддерживается для terraform. Поддерживаются: .terraform.lock.hcl, versions.tf, providers.tf",
		base)
}

func parseTerraformLock(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, match := range terraformLockProvider.FindAllSubmatch(content, -1) {
		out = append(out, direct(string(match[1]), strings.TrimPrefix(string(match[2]), "v")))
	}
	if len(out) == 0 {
		return parseTerraformCoordinates(content)
	}
	return dedupe(out, lowerNameVersionKey), nil
}

func parseTerraformCoordinates(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, line := range compactLines(content) {
		idx := strings.LastIndex(line, "@")
		if idx <= 0 || idx == len(line)-1 {
			return nil, invalidf(
				"Не удалось разобрать строку .terraform.lock.hcl: «%s». Ожидается namespace/name@version",
				line)
		}
		name := strings.TrimPrefix(strings.TrimSpace(line[:idx]), "registry.terraform.io/")
		version := strings.TrimSpace(line[idx+1:])
		if !strings.Contains(name, "/") || !compactTerraformVersion.MatchString(version) {
			return nil, invalidf(
				"Не удалось разобрать строку .terraform.lock.hcl: «%s». Ожидается namespace/name@version",
				line)
		}
		out = append(out, direct(name, strings.TrimPrefix(version, "v")))
	}
	if len(out) == 0 {
		return nil, invalidf("В .terraform.lock.hcl не найдено закреплённых провайдеров")
	}
	return dedupe(out, lowerNameVersionKey), nil
}

var terraformConfigProvider = regexp.MustCompile(`(?s)source\s*=\s*"([^"]+)".*?version\s*=\s*"([^"]+)"`)
var exactTerraformVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

func parseTerraformConfig(content []byte) ([]RawDependency, error) {
	var out []RawDependency
	for _, match := range terraformConfigProvider.FindAllSubmatch(content, -1) {
		name := strings.TrimPrefix(string(match[1]), "registry.terraform.io/")
		version := strings.TrimSpace(string(match[2]))
		version = strings.TrimSpace(strings.TrimPrefix(version, "="))
		if !exactTerraformVersion.MatchString(version) {
			out = append(out, unpinned(name,
				"«"+name+"»: «"+string(match[2])+"» — диапазон версий; укажите точную версию"))
			continue
		}
		out = append(out, direct(name, strings.TrimPrefix(version, "v")))
	}
	if len(out) == 0 {
		return nil, invalidf("В Terraform-конфигурации не найдено провайдеров с source и version")
	}
	return dedupe(out, lowerNameVersionKey), nil
}
