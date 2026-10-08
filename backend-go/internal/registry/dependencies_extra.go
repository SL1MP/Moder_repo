package registry

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------- maven

type mavenMetadata struct {
	Versioning struct {
		Versions []string `xml:"versions>version"`
	} `xml:"versioning"`
}

type mavenEffectiveModel struct {
	properties   map[string]string
	managed      map[string]string
	dependencies []mavenDependency
}

var mavenPropertyRef = regexp.MustCompile(`\$\{([^}]+)\}`)

func resolveMavenValue(value string, properties map[string]string) string {
	value = strings.TrimSpace(value)
	for pass := 0; pass < 12 && strings.Contains(value, "${"); pass++ {
		changed := false
		value = mavenPropertyRef.ReplaceAllStringFunc(value, func(token string) string {
			key := strings.TrimSuffix(strings.TrimPrefix(token, "${"), "}")
			if replacement, ok := properties[key]; ok {
				changed = true
				return replacement
			}
			return token
		})
		if !changed {
			break
		}
	}
	return strings.TrimSpace(value)
}

func copyStringMap(source map[string]string) map[string]string {
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func (p *Maven) effectiveModel(ctx context.Context, group, artifact, release string,
	visited map[string]bool, depth int) (mavenEffectiveModel, error) {
	if depth > mavenMaxParentDepth {
		return mavenEffectiveModel{}, fmt.Errorf("цепочка parent/BOM Maven длиннее %d", mavenMaxParentDepth)
	}
	key := mavenKey(group, artifact, release)
	if visited[key] {
		return mavenEffectiveModel{}, fmt.Errorf("цикл parent/BOM Maven: %s", key)
	}
	visited[key] = true
	defer delete(visited, key)

	body, _, err := p.fetchPOM(ctx, group, artifact, release)
	if err != nil {
		return mavenEffectiveModel{}, err
	}
	var pom mavenPOM
	if err := xml.Unmarshal(body, &pom); err != nil {
		return mavenEffectiveModel{}, fmt.Errorf("POM %s не разобран: %w", key, err)
	}

	model := mavenEffectiveModel{properties: map[string]string{}, managed: map[string]string{}}
	// CI-friendly POM часто записывает parent version как ${revision}, а
	// revision объявляет в собственном properties. Разрешаем эти значения до
	// похода за parent, иначе весь dependencyManagement родителя потеряется.
	bootstrap := copyStringMap(pom.Properties)
	bootstrap["project.groupId"] = group
	bootstrap["pom.groupId"] = group
	bootstrap["project.artifactId"] = artifact
	bootstrap["pom.artifactId"] = artifact
	bootstrap["project.version"] = release
	bootstrap["pom.version"] = release
	parentGroup := resolveMavenValue(pom.Parent.GroupID, bootstrap)
	parentArtifact := resolveMavenValue(pom.Parent.ArtifactID, bootstrap)
	parentVersion := resolveMavenValue(pom.Parent.Version, bootstrap)
	if parentGroup != "" && parentArtifact != "" && parentVersion != "" &&
		!strings.Contains(parentGroup+parentArtifact+parentVersion, "${") {
		parent, parentErr := p.effectiveModel(ctx, parentGroup, parentArtifact, parentVersion, visited, depth+1)
		if parentErr != nil {
			return mavenEffectiveModel{}, fmt.Errorf("parent POM %s:%s:%s: %w",
				parentGroup, parentArtifact, parentVersion, parentErr)
		}
		model.properties = copyStringMap(parent.properties)
		model.managed = copyStringMap(parent.managed)
		model.dependencies = append(model.dependencies, parent.dependencies...)
	}

	effectiveGroup := strings.TrimSpace(pom.GroupID)
	if effectiveGroup == "" {
		effectiveGroup = group
	}
	effectiveArtifact := strings.TrimSpace(pom.ArtifactID)
	if effectiveArtifact == "" {
		effectiveArtifact = artifact
	}
	effectiveVersion := strings.TrimSpace(pom.Version)
	if effectiveVersion == "" {
		effectiveVersion = release
	}
	for key, value := range map[string]string{
		"project.groupId": effectiveGroup, "pom.groupId": effectiveGroup,
		"project.artifactId": effectiveArtifact, "pom.artifactId": effectiveArtifact,
		"project.version": effectiveVersion, "pom.version": effectiveVersion,
		"parent.groupId": parentGroup, "project.parent.groupId": parentGroup,
		"parent.version": parentVersion, "project.parent.version": parentVersion,
	} {
		if value != "" {
			model.properties[key] = resolveMavenValue(value, model.properties)
		}
	}
	for prop, value := range pom.Properties {
		model.properties[prop] = resolveMavenValue(value, model.properties)
	}
	// Повторный проход разрешает свойства, которые объявлены раньше/позже
	// друг друга внутри одного блока properties.
	for prop, value := range model.properties {
		model.properties[prop] = resolveMavenValue(value, model.properties)
	}

	for _, dependency := range pom.DependencyManagement.Dependencies {
		depGroup := resolveMavenValue(dependency.GroupID, model.properties)
		depArtifact := resolveMavenValue(dependency.ArtifactID, model.properties)
		depVersion := resolveMavenValue(dependency.Version, model.properties)
		if depGroup == "" || depArtifact == "" || depVersion == "" {
			continue
		}
		if strings.EqualFold(resolveMavenValue(dependency.Type, model.properties), "pom") &&
			strings.EqualFold(resolveMavenValue(dependency.Scope, model.properties), "import") {
			bom, bomErr := p.effectiveModel(ctx, depGroup, depArtifact, depVersion, visited, depth+1)
			if bomErr != nil {
				return mavenEffectiveModel{}, fmt.Errorf("импортированный BOM %s:%s:%s: %w",
					depGroup, depArtifact, depVersion, bomErr)
			}
			for managedKey, managedVersion := range bom.managed {
				model.managed[managedKey] = managedVersion
			}
			continue
		}
		model.managed[depGroup+":"+depArtifact] = depVersion
	}
	for _, dependency := range pom.Dependencies {
		model.dependencies = append(model.dependencies, resolveMavenDependency(dependency, model.properties))
	}
	return model, nil
}

func resolveMavenDependency(dependency mavenDependency, properties map[string]string) mavenDependency {
	dependency.GroupID = resolveMavenValue(dependency.GroupID, properties)
	dependency.ArtifactID = resolveMavenValue(dependency.ArtifactID, properties)
	dependency.Version = resolveMavenValue(dependency.Version, properties)
	dependency.Scope = resolveMavenValue(dependency.Scope, properties)
	dependency.Type = resolveMavenValue(dependency.Type, properties)
	dependency.Optional = resolveMavenValue(dependency.Optional, properties)
	return dependency
}

func (p *Maven) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	group, artifact, ok := splitMavenName(ref.Name)
	if !ok {
		return nil, invalidFormat(p.EntryFormat(), "некорректная Maven-координата %q", ref.Name)
	}
	model, err := p.effectiveModel(ctx, group, artifact, ref.RawVersion, map[string]bool{}, 0)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]Requirement, 0, len(model.dependencies))
	for _, dependency := range model.dependencies {
		depGroup := resolveMavenValue(dependency.GroupID, model.properties)
		depArtifact := resolveMavenValue(dependency.ArtifactID, model.properties)
		if depGroup == "" || depArtifact == "" || strings.Contains(depGroup+depArtifact, "${") {
			continue
		}
		scope := strings.ToLower(resolveMavenValue(dependency.Scope, model.properties))
		if scope == "test" || scope == "provided" || scope == "system" || scope == "import" {
			continue
		}
		name := depGroup + ":" + depArtifact
		if seen[name] {
			continue
		}
		seen[name] = true
		constraint := resolveMavenValue(dependency.Version, model.properties)
		if constraint == "" {
			constraint = model.managed[name]
		}
		note := ""
		if constraint == "" || strings.Contains(constraint, "${") {
			// Специальное невалидное требование превращается в видимую Problem,
			// а не в случайный выбор самой новой версии.
			constraint = "<не удалось определить версию из POM>"
			note = "версия отсутствует в effective POM"
		}
		out = append(out, Requirement{
			Name: name, Constraint: constraint,
			Optional: strings.EqualFold(resolveMavenValue(dependency.Optional, model.properties), "true"),
			Note: note,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (p *Maven) Versions(ctx context.Context, name string) ([]string, error) {
	group, artifact, ok := splitMavenName(name)
	if !ok {
		return nil, invalidFormat(p.EntryFormat(), "некорректная Maven-координата %q", name)
	}
	seen := map[string]bool{}
	var out []string
	var lastErr error
	for _, base := range mavenBaseURLs(p.BaseURL) {
		metadataURL := fmt.Sprintf("%s/%s/%s/maven-metadata.xml", base, groupPath(group), artifact)
		body, err := getBytes(ctx, p.HTTP, metadataURL, "application/xml")
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}
		var metadata mavenMetadata
		if err := xml.Unmarshal(body, &metadata); err != nil {
			lastErr = fmt.Errorf("maven-metadata.xml %s не разобран: %w", metadataURL, err)
			continue
		}
		for _, candidate := range metadata.Versioning.Versions {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" && !seen[candidate] && !strings.HasSuffix(strings.ToUpper(candidate), "-SNAPSHOT") {
				seen[candidate] = true
				out = append(out, candidate)
			}
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// ---------------------------------------------------------------- luarocks

var luaDependencyString = regexp.MustCompile(`["']([^"']+)["']`)

func luaTable(source, field string) string {
	startRE := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(field) + `\s*=\s*\{`)
	match := startRE.FindStringIndex(source)
	if match == nil {
		return ""
	}
	open := strings.Index(source[match[0]:match[1]], "{") + match[0]
	depth := 0
	quote := byte(0)
	escaped := false
	for idx := open; idx < len(source); idx++ {
		char := source[idx]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			continue
		}
		switch char {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[open+1 : idx]
			}
		}
	}
	return ""
}

func parseLuaRequirement(value string) (Requirement, bool) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 || strings.EqualFold(fields[0], "lua") {
		return Requirement{}, false
	}
	return Requirement{Name: fields[0], Constraint: strings.TrimSpace(strings.TrimPrefix(value, fields[0]))}, true
}

func (p *LuaRocks) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	rockspecURL := fmt.Sprintf("%s/%s-%s.rockspec", strings.TrimRight(p.BaseURL, "/"), ref.Name, ref.Version)
	body, err := getBytes(ctx, p.HTTP, rockspecURL, "text/plain")
	if err != nil {
		return nil, err
	}
	table := luaTable(string(body), "dependencies")
	if table == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []Requirement
	for _, match := range luaDependencyString.FindAllStringSubmatch(table, -1) {
		requirement, ok := parseLuaRequirement(match[1])
		if !ok || seen[strings.ToLower(requirement.Name)] {
			continue
		}
		seen[strings.ToLower(requirement.Name)] = true
		out = append(out, requirement)
	}
	return out, nil
}

func luaNamedTable(source, name string) string {
	patterns := []string{
		`(?m)\[\s*["']` + regexp.QuoteMeta(name) + `["']\s*\]\s*=\s*\{`,
		`(?m)\b` + regexp.QuoteMeta(name) + `\s*=\s*\{`,
	}
	for _, pattern := range patterns {
		match := regexp.MustCompile(pattern).FindStringIndex(source)
		if match == nil {
			continue
		}
		prefix := source[:match[0]]
		field := "__moderation_selected_table_" + fmt.Sprint(len(prefix))
		// luaTable ищет имя поля; замена только найденного префикса позволяет
		// повторно использовать безопасный балансировщик фигурных скобок.
		rewritten := source[:match[0]] + field + " = {" + source[match[1]:]
		return luaTable(rewritten, field)
	}
	return ""
}

func (p *LuaRocks) Versions(ctx context.Context, name string) ([]string, error) {
	body, err := getBytes(ctx, p.HTTP, strings.TrimRight(p.BaseURL, "/")+"/manifest", "text/plain")
	if err != nil {
		return nil, err
	}
	packageTable := luaNamedTable(string(body), p.NormalizeName(name))
	if packageTable == "" {
		return nil, ErrNotFound
	}
	versionRE := regexp.MustCompile(`(?m)\[\s*["']([^"']+)["']\s*\]\s*=\s*\{`)
	seen := map[string]bool{}
	var out []string
	for _, match := range versionRE.FindAllStringSubmatch(packageTable, -1) {
		candidate := strings.TrimSpace(match[1])
		if luaRockVersionRe.MatchString(candidate) && !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// ---------------------------------------------------------------- composer

func composerVersions(payload composerPackage, name string) []string {
	list := payload.Packages[name]
	if len(list) == 0 {
		for _, candidate := range payload.Packages {
			list = candidate
			break
		}
	}
	out := make([]string, 0, len(list))
	seen := map[string]bool{}
	for _, release := range list {
		candidate := strings.TrimPrefix(strings.TrimSpace(release.Version), "v")
		if candidate == "" || strings.Contains(strings.ToLower(candidate), "dev") || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	return out
}

func (p *PHP) loadComposerPackage(ctx context.Context, name string) (composerPackage, error) {
	var payload composerPackage
	url := fmt.Sprintf("%s/p2/%s.json", strings.TrimRight(p.BaseURL, "/"), p.NormalizeName(name))
	if err := getJSON(ctx, p.HTTP, url, "application/json", &payload); err != nil {
		return composerPackage{}, err
	}
	return payload, nil
}

func composerPlatformRequirement(name string) bool {
	lower := strings.ToLower(name)
	return lower == "php" || lower == "php-64bit" || lower == "hhvm" ||
		strings.HasPrefix(lower, "ext-") || strings.HasPrefix(lower, "lib-") ||
		strings.HasPrefix(lower, "composer-")
}

func (p *PHP) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	payload, err := p.loadComposerPackage(ctx, ref.Name)
	if err != nil {
		return nil, err
	}
	list := payload.Packages[ref.Name]
	if len(list) == 0 {
		for _, candidate := range payload.Packages {
			list = candidate
			break
		}
	}
	current := map[string]string(nil)
	for _, release := range list {
		if composerFieldUnset(release.Unset, "require") {
			current = nil
		}
		if release.Require != nil {
			current = make(map[string]string, len(*release.Require))
			for name, constraint := range *release.Require {
				current[name] = constraint
			}
		}
		if payload.Minified != "composer/2.0" && release.Require == nil {
			current = nil
		}
		if p.NormalizeVersion(release.Version) != ref.Version &&
			!strings.HasPrefix(release.VersionNormalized, ref.Version+".") &&
			release.VersionNormalized != ref.Version {
			continue
		}
		var out []Requirement
		for name, constraint := range current {
			if composerPlatformRequirement(name) {
				continue
			}
			out = append(out, Requirement{Name: name, Constraint: constraint})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
	return nil, fmt.Errorf("%w: версии %s пакета %s нет в Packagist", ErrNotFound, ref.RawVersion, ref.DisplayName)
}

func (p *PHP) Versions(ctx context.Context, name string) ([]string, error) {
	payload, err := p.loadComposerPackage(ctx, name)
	if err != nil {
		return nil, err
	}
	versions := composerVersions(payload, p.NormalizeName(name))
	if len(versions) == 0 {
		return nil, ErrNotFound
	}
	return versions, nil
}

// ---------------------------------------------------------------- terraform

// Provider Registry Protocol не содержит зависимостей одного provider от
// другого: провайдер — самостоятельный плагин Terraform. Поэтому поддержка
// раскрытия здесь означает проверенный по реестру пустой граф, а зависимости
// проекта извлекаются из .terraform.lock.hcl как отдельные корневые пакеты.
func (p *Terraform) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	_, _, err := p.versionPlatforms(ctx, ref)
	return nil, err
}

func (p *Terraform) Versions(ctx context.Context, name string) ([]string, error) {
	base := p.providerAPIBase(ctx)
	var response terraformVersions
	if err := getJSONWithHeaders(ctx, p.HTTP, fmt.Sprintf("%s/%s/versions", base, p.NormalizeName(name)),
		"application/json", terraformRegistryHeaders, &response); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, release := range response.Versions {
		candidate := strings.TrimPrefix(strings.TrimSpace(release.Version), "v")
		if candidate != "" && !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}
