package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	nugetIDRe      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	nugetVersionRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?(\.\d+)?(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$`)
)

// NuGet — плагин менеджера nuget. Формат записи: Id@version.
type NuGet struct {
	BaseURL string
	HTTP    Doer
}

func (*NuGet) Code() string         { return "nuget" }
func (*NuGet) Title() string        { return "NuGet (.NET)" }
func (*NuGet) EntryFormat() string  { return "Id@version" }
func (*NuGet) OSVEcosystem() string { return "NuGet" }

func (*NuGet) NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
func (*NuGet) NormalizeVersion(version string) string {
	return strings.ToLower(strings.TrimSpace(version))
}
func (*NuGet) DisplayName(name string) string { return strings.TrimSpace(name) }

func (p *NuGet) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, "@")
	if idx < 0 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату nuget. Ожидается: Id@version "+
				"(например, Newtonsoft.Json@13.0.3)", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *NuGet) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя пакета длиннее 512 символов")
	}
	if !nugetIDRe.MatchString(name) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимый Id пакета nuget: «%s» (буквы, цифры, «.», «-», «_»)", name)
	}
	return nil
}

func (p *NuGet) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	if !nugetVersionRe.MatchString(strings.TrimSpace(version)) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует формату nuget (например, 13.0.3, 6.0.0-preview.5)", version)
	}
	return nil
}

// nugetRegistration — ответ registration-эндпоинта. catalogEntry бывает и
// объектом, и ссылкой на него — отсюда json.RawMessage.
type nugetRegistration struct {
	CatalogEntry   json.RawMessage `json:"catalogEntry"`
	PackageContent string          `json:"packageContent"`
}

type nugetCatalogEntry struct {
	Published         string `json:"published"`
	LicenseExpression string `json:"licenseExpression"`
	LicenseURL        string `json:"licenseUrl"`
	PackageContent    string `json:"packageContent"`
	Listed            *bool  `json:"listed"`
}

func (p *NuGet) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	url := fmt.Sprintf("%s/v3/registration5-semver1/%s/%s.json", p.BaseURL, ref.Name, ref.Version)
	var payload nugetRegistration
	if err := getJSON(ctx, p.HTTP, url, "application/json", &payload); err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf("%w: пакет %s@%s отсутствует в реестре nuget",
				ErrNotFound, ref.DisplayName, ref.RawVersion)
		}
		return Metadata{}, err
	}

	entry, err := p.resolveCatalogEntry(ctx, payload.CatalogEntry)
	if err != nil {
		return Metadata{}, err
	}

	content := payload.PackageContent
	if content == "" {
		content = entry.PackageContent
	}
	if content == "" {
		content = fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s.%s.nupkg",
			p.BaseURL, ref.Name, ref.Version, ref.Name, ref.Version)
	}

	meta := Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		PublishedAt:      parseTime(entry.Published),
		ArtifactURL:      content,
		ArtifactFilename: fmt.Sprintf("%s.%s.nupkg", ref.Name, ref.Version),
		LicenseSPDX:      NormalizeSPDX(entry.LicenseExpression),
		// NuGet отдаёт хеш только внутри манифеста .nupkg — sha256 считаем
		// сами по скачанному артефакту.
		Yanked: entry.Listed != nil && !*entry.Listed,
	}
	meta.LicenseRaw = entry.LicenseExpression
	if meta.LicenseRaw == "" {
		meta.LicenseRaw = entry.LicenseURL
	}
	return meta, nil
}

// resolveCatalogEntry разбирает catalogEntry: объектом — разбираем на месте,
// строкой — это ссылка, ходим за ней. Недоступность каталога по ссылке не
// валит шаг: путь к артефакту и так известен, а лицензию определит юрист.
func (p *NuGet) resolveCatalogEntry(ctx context.Context, raw json.RawMessage) (nugetCatalogEntry, error) {
	var entry nugetCatalogEntry
	if len(raw) == 0 {
		return entry, nil
	}
	var link string
	if err := json.Unmarshal(raw, &link); err == nil {
		if err := getJSON(ctx, p.HTTP, link, "application/json", &entry); err != nil {
			return nugetCatalogEntry{}, nil //nolint:nilerr // см. комментарий выше
		}
		return entry, nil
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return entry, fmt.Errorf("catalogEntry реестра nuget не разобран: %w", err)
	}
	return entry, nil
}

func (p *NuGet) InstallCommand(ref Ref, baseURL, repo string) string {
	source := fmt.Sprintf("%s/repository/%s/index.json", strings.TrimRight(baseURL, "/"), repo)
	return fmt.Sprintf("dotnet nuget add source %s -n internal && dotnet add package %s -v %s -s %s",
		source, ref.DisplayName, ref.RawVersion, source)
}

func (p *NuGet) ArtifactPath(ref Ref, filename string) string {
	return fmt.Sprintf("%s/%s/%s", ref.Name, ref.Version, filename)
}
