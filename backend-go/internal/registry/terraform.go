package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
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
// Платформу в записи оставляем для обратной совместимости и явной проверки её
// наличия. Скачивание и публикация при этом всегда охватывают ВСЕ платформы
// версии: внутренний network mirror должен быть пригоден разработчикам на
// Linux, Windows и macOS, а не только машине worker-go.
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

// terraformVersions — обязательный ответ Provider Registry Protocol. Именно
// список versions/platforms является источником истины о существовании версии;
// проверка одного /download/linux/amd64 давала ложный «не найден» для реально
// опубликованных провайдеров.
type terraformVersions struct {
	Versions []struct {
		Version   string `json:"version"`
		Protocols []string `json:"protocols"`
		Platforms []struct {
			OS   string `json:"os"`
			Arch string `json:"arch"`
		} `json:"platforms"`
	} `json:"versions"`
}

type terraformPlatform struct {
	OS   string
	Arch string
}

type terraformMirrorVersion struct {
	Archives map[string]terraformMirrorArchive `json:"archives"`
}

type terraformMirrorArchive struct {
	URL    string   `json:"url"`
	Hashes []string `json:"hashes"`
}

type terraformMirrorIndex struct {
	Versions map[string]struct{} `json:"versions"`
}

// terraformVersionInfo — ответ о самой версии; из него берём дату публикации.
type terraformVersionInfo struct {
	Version     string `json:"version"`
	PublishedAt string `json:"published_at"`
	Source      string `json:"source"`
}

var terraformRegistryHeaders = map[string]string{
	// Provider Registry Protocol требует, чтобы клиент сообщал версию
	// Terraform. Публичный registry.terraform.io обычно прощает отсутствие
	// заголовка, но зеркала и WAF нередко отвечают на такой запрос ложным 404.
	"X-Terraform-Version": "1.9.8",
	"User-Agent":          "Terraform/1.9.8 moderation-service/1.0",
}

// terraformAPIBase принимает и адрес сервиса, и адрес API из старых .env:
// https://registry.terraform.io, .../v1 или .../v1/providers. Без
// нормализации последний вариант превращался в /v1/providers/v1/providers/…
// и любая существующая версия выглядела отсутствующей.
func terraformAPIBase(value string) string {
	base := strings.TrimRight(strings.TrimSpace(value), "/")
	base = strings.TrimSuffix(base, "/v1/providers")
	base = strings.TrimSuffix(base, "/v1")
	return strings.TrimRight(base, "/")
}

func (p *Terraform) versionPlatforms(ctx context.Context, ref Ref) (string, []terraformPlatform, error) {
	version, requestedPlatform := splitTerraformVersion(ref.Version)
	base := terraformAPIBase(p.BaseURL)
	var response terraformVersions
	if err := getJSONWithHeaders(ctx, p.HTTP,
		fmt.Sprintf("%s/v1/providers/%s/versions", base, ref.Name),
		"application/json", terraformRegistryHeaders, &response); err != nil {
		if err == ErrNotFound {
			return "", nil, fmt.Errorf("%w: провайдер %s не найден в реестре terraform",
				ErrNotFound, ref.DisplayName)
		}
		return "", nil, err
	}
	var platforms []terraformPlatform
	for _, candidate := range response.Versions {
		if strings.TrimPrefix(candidate.Version, "v") != version {
			continue
		}
		seen := map[string]bool{}
		for _, platform := range candidate.Platforms {
			key := platform.OS + "_" + platform.Arch
			if platform.OS == "" || platform.Arch == "" || seen[key] {
				continue
			}
			seen[key] = true
			platforms = append(platforms, terraformPlatform{OS: platform.OS, Arch: platform.Arch})
		}
		break
	}
	if len(platforms) == 0 {
		return "", nil, fmt.Errorf("%w: провайдера %s версии %s нет в реестре terraform",
			ErrNotFound, ref.DisplayName, version)
	}
	sort.Slice(platforms, func(i, j int) bool {
		return platforms[i].OS+"_"+platforms[i].Arch < platforms[j].OS+"_"+platforms[j].Arch
	})
	if requestedPlatform != "" {
		found := false
		for _, platform := range platforms {
			if platform.OS+"_"+platform.Arch == requestedPlatform {
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("%w: провайдера %s версии %s под %s нет в реестре terraform",
				ErrNotFound, ref.DisplayName, version, requestedPlatform)
		}
	}
	return version, platforms, nil
}

func (p *Terraform) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	version, _, err := p.versionPlatforms(ctx, ref)
	if err != nil {
		return Metadata{}, err
	}
	base := terraformAPIBase(p.BaseURL)
	meta := Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		ArtifactURL:      fmt.Sprintf("%s/v1/providers/%s/%s", base, ref.Name, version),
		ArtifactFilename: fmt.Sprintf("terraform-provider-%s_%s.terraform-release.tgz",
			providerShortName(ref.Name), version),
	}

	// Дата публикации — отдельным запросом: в ответе о дистрибутиве её нет.
	// Недоступность этого запроса не валит шаг: карантин будет пропущен с
	// пометкой, а пакет всё равно проверится.
	var info terraformVersionInfo
	if err := getJSONWithHeaders(ctx, p.HTTP,
		fmt.Sprintf("%s/v1/providers/%s/%s", base, ref.Name, version),
		"application/json", terraformRegistryHeaders, &info); err == nil {
		meta.PublishedAt = parseTime(info.PublishedAt)
	}
	return meta, nil
}

func (*Terraform) ReleaseBundle() {}

// Download собирает статическое network mirror: архивы всех платформ и два
// JSON-файла протокола зеркала. В staging это один transport bundle; при
// публикации он раскладывается обратно в реальные файлы.
func (p *Terraform) Download(ctx context.Context, ref Ref, limit int64) ([]byte, string, error) {
	version, platforms, err := p.versionPlatforms(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	base := terraformAPIBase(p.BaseURL)
	files := make([]BundleFile, 0, len(platforms)+2)
	mirror := terraformMirrorVersion{Archives: make(map[string]terraformMirrorArchive, len(platforms))}
	usedNames := map[string]bool{}

	for _, platform := range platforms {
		platformKey := platform.OS + "_" + platform.Arch
		var dist terraformDownload
		endpoint := fmt.Sprintf("%s/v1/providers/%s/%s/download/%s/%s",
			base, ref.Name, version, platform.OS, platform.Arch)
		if err := getJSONWithHeaders(ctx, p.HTTP, endpoint, "application/json",
			terraformRegistryHeaders, &dist); err != nil {
			return nil, "", fmt.Errorf("метаданные дистрибутива Terraform %s: %w", platformKey, err)
		}
		if dist.DownloadURL == "" {
			return nil, "", fmt.Errorf("реестр terraform не сообщил download_url для %s", platformKey)
		}
		filename := safeFilename(dist.Filename)
		if dist.Filename == "" {
			filename = fmt.Sprintf("terraform-provider-%s_%s_%s_%s.zip",
				providerShortName(ref.Name), version, platform.OS, platform.Arch)
		}
		if usedNames[filename] {
			return nil, "", fmt.Errorf("реестр terraform вернул одинаковое имя %s для нескольких платформ", filename)
		}
		remaining := remainingLimit(limit, bundleFilesMap(files))
		if limit > 0 && remaining <= 0 {
			return nil, "", fmt.Errorf("Terraform-релиз больше допустимого предела %d байт", limit)
		}
		body, err := getBytesWithLimitAndHeaders(ctx, p.HTTP, dist.DownloadURL,
			"application/octet-stream", remaining, terraformRegistryHeaders)
		if err != nil {
			return nil, "", fmt.Errorf("скачивание Terraform %s: %w", platformKey, err)
		}
		digest := sha256.Sum256(body)
		actual := hex.EncodeToString(digest[:])
		if dist.SHASum != "" && !strings.EqualFold(strings.TrimSpace(dist.SHASum), actual) {
			return nil, "", fmt.Errorf("sha256 Terraform %s не совпала: ожидалось %s, получено %s",
				platformKey, dist.SHASum, actual)
		}
		usedNames[filename] = true
		files = append(files, BundleFile{Name: filename, Data: body})
		mirror.Archives[platformKey] = terraformMirrorArchive{
			URL: version + "/" + filename, Hashes: []string{"zh:" + actual},
		}
	}

	versionJSON, err := json.Marshal(mirror)
	if err != nil {
		return nil, "", err
	}
	indexJSON, err := json.Marshal(terraformMirrorIndex{Versions: map[string]struct{}{version: {}}})
	if err != nil {
		return nil, "", err
	}
	files = append(files,
		BundleFile{Name: version + ".json", Data: versionJSON},
		BundleFile{Name: "index.json", Data: indexJSON},
	)
	bundle, err := PackBundle("terraform", files, limit)
	if err != nil {
		return nil, "", err
	}
	return bundle, fmt.Sprintf("terraform-provider-%s_%s.terraform-release.tgz",
		providerShortName(ref.Name), version), nil
}

func bundleFilesMap(files []BundleFile) map[string][]byte {
	out := make(map[string][]byte, len(files))
	for _, file := range files {
		out[file.Name] = file.Data
	}
	return out
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
		"укажите зеркало %s/repository/%s/ в ~/.terraformrc (provider_installation → network_mirror) "+
			"и требование source = \"%s\", version = \"%s\"",
		strings.TrimRight(baseURL, "/"), repo, ref.DisplayName, version)
}

func (p *Terraform) ArtifactPath(ref Ref, filename string) string {
	version, _ := splitTerraformVersion(ref.Version)
	return fmt.Sprintf("registry.terraform.io/%s/%s/%s", ref.Name, version, filename)
}
