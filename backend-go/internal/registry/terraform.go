package registry

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	terraformNameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9-]*$`)
	terraformVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?$`)
)

// Terraform — плагин провайдеров Terraform. Формат записи:
// namespace/name@version[:os_arch].
//
// Провайдеры, а не модули: модуль Terraform — это архив исходников без
// бинарного дистрибутива, и проверять в нём нечего, кроме текста. Провайдер —
// исполняемый файл на каждую платформу, и вот он модерации подлежит.
//
// Платформа — часть записи, потому что дистрибутивы у платформ РАЗНЫЕ БАЙТЫ с
// разными контрольными суммами. Решение по linux_amd64 ничего не говорит о
// windows_amd64, и делать вид, что говорит, нельзя. По умолчанию берётся
// linux_amd64 — то, что реально исполняется на серверах сборки.
type Terraform struct {
	// BaseURL — реестр Terraform или внутреннее зеркало.
	BaseURL string
	HTTP    Doer
	// DefaultPlatform — платформа, если её не указали в записи.
	DefaultPlatform string
}

func (*Terraform) Code() string  { return "terraform" }
func (*Terraform) Title() string { return "Terraform (провайдеры)" }

func (*Terraform) EntryFormat() string { return "namespace/name@version[:os_arch]" }

// OSVEcosystem — своей экосистемы у Terraform в OSV нет. Пустая строка честнее
// выдуманного имени: шаг уязвимостей отличит «в базе ничего не нашлось» от
// «эту экосистему база не покрывает».
func (*Terraform) OSVEcosystem() string { return "" }

func (*Terraform) NormalizeName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// NormalizeVersion — ведущая «v» в реестре Terraform необязательна.
func (*Terraform) NormalizeVersion(version string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
}

func (*Terraform) DisplayName(name string) string { return strings.TrimSpace(name) }

func (*Terraform) DependencyFiles() []string {
	return []string{".terraform.lock.hcl", "versions.tf", "providers.tf"}
}

func (p *Terraform) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, "@")
	if idx < 0 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату terraform. Ожидается: namespace/name@version "+
				"(например, hashicorp/aws@5.31.0) — платформу можно дописать через "+
				"двоеточие: hashicorp/aws@5.31.0:linux_amd64", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *Terraform) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя провайдера длиннее 512 символов")
	}
	if !terraformNameRe.MatchString(strings.ToLower(name)) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимое имя провайдера: «%s» (ожидается namespace/name, например hashicorp/aws)", name)
	}
	return nil
}

func (p *Terraform) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	version, platform := splitTerraformVersion(version)
	if !terraformVersionRe.MatchString(version) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует формату terraform (например, 5.31.0)", version)
	}
	if platform != "" && !strings.Contains(platform, "_") {
		return invalidFormat(p.EntryFormat(),
			"Платформа «%s» записана неверно: ожидается os_arch, например linux_amd64", platform)
	}
	return nil
}

// splitTerraformVersion отделяет платформу от версии: «5.31.0:linux_amd64».
func splitTerraformVersion(version string) (string, string) {
	if idx := strings.Index(version, ":"); idx >= 0 {
		return strings.TrimSpace(version[:idx]), strings.TrimSpace(version[idx+1:])
	}
	return strings.TrimSpace(version), ""
}

func (p *Terraform) platform(version string) (os, arch string) {
	_, platform := splitTerraformVersion(version)
	if platform == "" {
		platform = p.DefaultPlatform
	}
	if platform == "" {
		platform = "linux_amd64"
	}
	parts := strings.SplitN(platform, "_", 2)
	if len(parts) != 2 {
		return "linux", "amd64"
	}
	return parts[0], parts[1]
}

// terraformDownload — ответ реестра о дистрибутиве под одну платформу.
type terraformDownload struct {
	Protocols   []string `json:"protocols"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	Filename    string   `json:"filename"`
	DownloadURL string   `json:"download_url"`
	SHASum      string   `json:"shasum"`
}

// terraformVersionInfo — ответ о самой версии; из него берём дату публикации.
type terraformVersionInfo struct {
	Version     string `json:"version"`
	PublishedAt string `json:"published_at"`
	Source      string `json:"source"`
}

func (p *Terraform) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	version, _ := splitTerraformVersion(ref.Version)
	osName, arch := p.platform(ref.Version)
	base := strings.TrimRight(p.BaseURL, "/")

	url := fmt.Sprintf("%s/v1/providers/%s/%s/download/%s/%s", base, ref.Name, version, osName, arch)
	var dist terraformDownload
	if err := getJSON(ctx, p.HTTP, url, "application/json", &dist); err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf(
				"%w: провайдера %s версии %s под %s_%s нет в реестре terraform",
				ErrNotFound, ref.DisplayName, version, osName, arch)
		}
		return Metadata{}, err
	}
	if dist.DownloadURL == "" {
		return Metadata{}, fmt.Errorf(
			"реестр terraform не сообщил ссылку на дистрибутив %s %s под %s_%s",
			ref.DisplayName, version, osName, arch)
	}

	filename := dist.Filename
	if filename == "" {
		filename = fmt.Sprintf("terraform-provider-%s_%s_%s_%s.zip",
			providerShortName(ref.Name), version, osName, arch)
	}
	meta := Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		ArtifactURL:      dist.DownloadURL,
		ArtifactFilename: filename,
	}
	if dist.SHASum != "" {
		meta.Checksum, meta.ChecksumAlgo = dist.SHASum, "sha256"
	}

	// Дата публикации — отдельным запросом: в ответе о дистрибутиве её нет.
	// Недоступность этого запроса не валит шаг: карантин будет пропущен с
	// пометкой, а пакет всё равно проверится.
	var info terraformVersionInfo
	if err := getJSON(ctx, p.HTTP,
		fmt.Sprintf("%s/v1/providers/%s/%s", base, ref.Name, version),
		"application/json", &info); err == nil {
		meta.PublishedAt = parseTime(info.PublishedAt)
	}
	return meta, nil
}

// providerShortName — «aws» из «hashicorp/aws».
func providerShortName(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

func (p *Terraform) InstallCommand(ref Ref, baseURL, repo string) string {
	version, _ := splitTerraformVersion(ref.Version)
	return fmt.Sprintf(
		"укажите зеркало %s/repository/%s в ~/.terraformrc (provider_installation → network_mirror) "+
			"и требование source = \"%s\", version = \"%s\"",
		strings.TrimRight(baseURL, "/"), repo, ref.DisplayName, version)
}

func (p *Terraform) ArtifactPath(ref Ref, filename string) string {
	version, _ := splitTerraformVersion(ref.Version)
	return fmt.Sprintf("%s/%s/%s", ref.Name, version, filename)
}
