package maintenance

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"moderation/internal/artifactstore"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

// CatalogConfig явно перечисляет доверенные moderated-репозитории. Сам факт
// присутствия файла в таком репозитории достаточен для появления версии в
// web-базе как approved; конвейер модерации здесь не запускается.
type CatalogConfig struct {
	Managers     []string
	Repositories map[string]string
	Registry     *registry.Registry
}

type catalogCoordinate struct {
	Name, Version string
}

var (
	pypiWheelName = regexp.MustCompile(`^([A-Za-z0-9_.]+)-([0-9][A-Za-z0-9.!+_]*)-[^-]+-[^-]+-[^-]+\.whl$`)
	pypiSdistName = regexp.MustCompile(`^(.+)-([0-9][A-Za-z0-9.!+_-]*)\.(?:tar\.gz|zip)$`)
)

// SyncTrustedCatalog выполняет один полный аддитивный обход. Отсутствующие в
// текущем ответе объекты не удаляются: временная ошибка прав/сети не должна
// скрывать уже доступный пакет из web-базы.
func (s *Service) SyncTrustedCatalog(
	ctx context.Context, cfg CatalogConfig, run *repo.CatalogSyncRun,
) (repo.CatalogSyncRun, error) {
	result := *run
	result.Details = map[string]any{"managers": map[string]any{}}
	if s.Artifacts == nil {
		return result, errors.New("клиент внутреннего артефактори не настроен")
	}
	if cfg.Registry == nil {
		return result, errors.New("реестр пакетных менеджеров не настроен")
	}
	if len(cfg.Managers) == 0 {
		return result, errors.New("ARTIFACT_CATALOG_SYNC_MANAGERS пуст: доверенные репозитории не выбраны")
	}

	managerDetails := result.Details["managers"].(map[string]any)
	succeededRepos := 0
	var repoErrors []error
	for _, manager := range cfg.Managers {
		repository := strings.TrimSpace(cfg.Repositories[manager])
		detail := map[string]any{"repository": repository}
		managerDetails[manager] = detail
		if repository == "" {
			result.Errors++
			detail["error"] = "целевой репозиторий не настроен"
			repoErrors = append(repoErrors, fmt.Errorf("%s: целевой репозиторий не настроен", manager))
			continue
		}
		plugin, err := cfg.Registry.Get(manager)
		if err != nil {
			result.Errors++
			detail["error"] = err.Error()
			repoErrors = append(repoErrors, fmt.Errorf("%s: %w", manager, err))
			continue
		}
		files, err := s.Artifacts.ListFiles(ctx, repository, "")
		if err != nil {
			result.Errors++
			detail["error"] = err.Error()
			repoErrors = append(repoErrors, fmt.Errorf("%s/%s: %w", manager, repository, err))
			continue
		}
		succeededRepos++
		detail["files"] = len(files)
		parsed, imported, updated, skipped, failures := 0, 0, 0, 0, 0
		warnings := make([]string, 0)
		versions := map[string][]repo.CatalogArtifact{}
		for _, file := range files {
			coordinate, ok := parseCatalogPath(manager, file.Path)
			if !ok {
				skipped++
				continue
			}
			parsed++
			result.Discovered++
			displayName := strings.TrimSpace(coordinate.Name)
			normalizedName := plugin.NormalizeName(displayName)
			normalizedVersion := plugin.NormalizeVersion(coordinate.Version)
			if normalizedName == "" || normalizedVersion == "" {
				skipped++
				continue
			}
			target := artifactstore.Target{
				Repo: repository, Manager: manager, Name: normalizedName,
				DisplayName: displayName, Version: coordinate.Version,
				Filename: path.Base(file.Path), Path: file.Path,
			}
			artifact := repo.CatalogArtifact{
				Manager: manager, Name: normalizedName, DisplayName: displayName,
				Version: normalizedVersion, RawVersion: coordinate.Version,
				Filename: path.Base(file.Path), URL: s.Artifacts.ArtifactURL(target),
				SizeBytes: file.SizeBytes, SHA256: file.Checksum,
				PublishedAt: file.LastModified,
			}
			versionKey := normalizedName + "\x00" + normalizedVersion
			versions[versionKey] = append(versions[versionKey], artifact)
		}
		versionKeys := make([]string, 0, len(versions))
		for versionKey := range versions {
			versionKeys = append(versionKeys, versionKey)
		}
		sort.Strings(versionKeys)
		for _, versionKey := range versionKeys {
			versionArtifacts := versions[versionKey]
			upserted, err := s.Repo.UpsertTrustedCatalogArtifacts(ctx, versionArtifacts, s.now())
			if err != nil {
				failures++
				result.Errors++
				if len(repoErrors) < 20 {
					repoErrors = append(repoErrors, fmt.Errorf("%s/%s: %w",
						manager, versionArtifacts[0].DisplayName, err))
				}
				if len(warnings) < 20 {
					warnings = append(warnings, versionArtifacts[0].DisplayName+"@"+
						versionArtifacts[0].RawVersion+": "+err.Error())
				}
				continue
			}
			if upserted.Imported {
				imported++
				result.Imported++
			} else {
				updated++
				result.Updated++
			}
		}
		result.Skipped += skipped
		detail["parsed"] = parsed
		detail["imported"] = imported
		detail["updated"] = updated
		detail["skipped"] = skipped
		detail["errors"] = failures
		if len(warnings) > 0 {
			detail["warnings"] = warnings
		}
	}

	s.audit(ctx, "artifact_catalog_synchronized", "artifact_catalog", "",
		map[string]any{"run_id": run.ID, "managers": cfg.Managers,
			"discovered": result.Discovered, "imported": result.Imported,
			"updated": result.Updated, "skipped": result.Skipped, "errors": result.Errors})
	if succeededRepos == 0 {
		return result, fmt.Errorf("ни один доверенный репозиторий не прочитан: %w", errors.Join(repoErrors...))
	}
	if len(repoErrors) > 0 {
		return result, fmt.Errorf("каталог синхронизирован частично: %w", errors.Join(repoErrors...))
	}
	return result, nil
}

func parseCatalogPath(manager, filePath string) (catalogCoordinate, bool) {
	clean := strings.Trim(strings.TrimSpace(filePath), "/")
	if clean == "" {
		return catalogCoordinate{}, false
	}
	parts := strings.Split(clean, "/")
	filename := parts[len(parts)-1]
	switch manager {
	case "pypi":
		// У нативного JFrog путь может отличаться, поэтому сначала читаем
		// самодостаточное имя wheel/sdist, а нашу name/version/file раскладку
		// используем как fallback.
		if match := pypiWheelName.FindStringSubmatch(filename); len(match) == 3 {
			return catalogCoordinate{Name: strings.ReplaceAll(match[1], "_", "-"), Version: match[2]}, true
		}
		if match := pypiSdistName.FindStringSubmatch(filename); len(match) == 3 {
			return catalogCoordinate{Name: match[1], Version: match[2]}, true
		}
		if len(parts) >= 3 {
			return catalogCoordinate{Name: strings.Join(parts[:len(parts)-2], "/"), Version: parts[len(parts)-2]}, true
		}
	case "npm":
		for i := range parts {
			if parts[i] != "-" || i == 0 || i+1 != len(parts)-1 {
				continue
			}
			name := strings.Join(parts[:i], "/")
			baseName := path.Base(name)
			if !strings.HasSuffix(filename, ".tgz") || !strings.HasPrefix(filename, baseName+"-") {
				return catalogCoordinate{}, false
			}
			version := strings.TrimSuffix(strings.TrimPrefix(filename, baseName+"-"), ".tgz")
			return catalogCoordinate{Name: name, Version: version}, version != ""
		}
	case "go":
		for i := range parts {
			if parts[i] != "@v" || i == 0 || i+1 != len(parts)-1 {
				continue
			}
			version := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(filename, ".zip"), ".mod"), ".info")
			if version == filename {
				return catalogCoordinate{}, false
			}
			return catalogCoordinate{Name: unescapeGoModule(strings.Join(parts[:i], "/")), Version: unescapeGoModule(version)}, true
		}
	case "maven":
		if len(parts) >= 4 && registry.AllowedMavenAsset(filename) {
			artifact, version := parts[len(parts)-3], parts[len(parts)-2]
			group := strings.Join(parts[:len(parts)-3], ".")
			return catalogCoordinate{Name: group + ":" + artifact, Version: version}, group != ""
		}
	case "nuget", "conan", "php":
		if len(parts) >= 3 {
			return catalogCoordinate{Name: strings.Join(parts[:len(parts)-2], "/"), Version: parts[len(parts)-2]}, true
		}
	case "terraform":
		if len(parts) >= 5 && parts[0] == "registry.terraform.io" {
			return catalogCoordinate{Name: parts[1] + "/" + parts[2], Version: parts[3]}, true
		}
	case "luarocks":
		// name-version-revision.(src|all).rock либо name-version.rockspec.
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(filename, ".src.rock"), ".all.rock"), ".rockspec")
		fields := strings.Split(base, "-")
		for i := len(fields) - 1; i > 0; i-- {
			if len(fields[i]) > 0 && fields[i][0] >= '0' && fields[i][0] <= '9' {
				name, version := strings.Join(fields[:i], "-"), strings.Join(fields[i:], "-")
				return catalogCoordinate{Name: name, Version: version}, name != ""
			}
		}
	}
	return catalogCoordinate{}, false
}

func unescapeGoModule(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '!' && i+1 < len(value) && value[i+1] >= 'a' && value[i+1] <= 'z' {
			b.WriteByte(value[i+1] - ('a' - 'A'))
			i++
			continue
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

// CatalogSyncTimeout учитывает большой первоначальный импорт корпоративной
// базы. Он ограничен, но заметно длиннее одного HTTP-запроса.
const CatalogSyncTimeout = 2 * time.Hour
