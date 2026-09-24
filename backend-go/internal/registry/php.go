package registry

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	// Packagist: vendor/package, оба — строчные буквы, цифры, «-», «_», «.».
	composerNameRe    = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)
	composerVersionRe = regexp.MustCompile(`^v?\d+(\.\d+){0,3}(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$`)
)

// PHP — плагин менеджера composer (реестр Packagist). Формат записи:
// vendor/package:version.
//
// Двоеточие, а не «@»: так зависимость пишут в composer.json и в
// `composer require`. См. ту же причину у maven.
type PHP struct {
	// BaseURL — репозиторий метаданных Packagist или внутреннее зеркало.
	BaseURL string
	HTTP    Doer
}

func (*PHP) Code() string         { return "php" }
func (*PHP) Title() string        { return "Composer (PHP)" }
func (*PHP) EntryFormat() string  { return "vendor/package:version" }
func (*PHP) OSVEcosystem() string { return "" }

// NormalizeName — Packagist имена регистронезависимы и канонично пишутся
// строчными.
func (*PHP) NormalizeName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// NormalizeVersion — ведущая «v» в composer необязательна и означает то же
// самое: v1.2.3 и 1.2.3 — одна версия, и разводить их по двум строкам в базе
// значило бы модерировать один пакет дважды.
func (*PHP) NormalizeVersion(version string) string {
	return strings.TrimPrefix(strings.TrimSpace(version), "v")
}

func (*PHP) DisplayName(name string) string { return strings.TrimSpace(name) }

func (*PHP) DependencyFiles() []string { return []string{"composer.json", "composer.lock"} }

func (p *PHP) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, ":")
	if idx < 0 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату composer. Ожидается: vendor/package:version "+
				"(например, symfony/console:6.4.2)", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *PHP) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя пакета длиннее 512 символов")
	}
	if !composerNameRe.MatchString(strings.ToLower(name)) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимое имя пакета composer: «%s» (ожидается vendor/package строчными)", name)
	}
	return nil
}

func (p *PHP) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	if !composerVersionRe.MatchString(version) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует формату composer (например, 6.4.2, v2.0.0-beta1)", version)
	}
	// dev-ветки меняются под тем же именем — промодерировать их невозможно,
	// см. ту же причину у SNAPSHOT в maven.
	if strings.HasPrefix(strings.ToLower(version), "dev-") ||
		strings.HasSuffix(strings.ToLower(version), "-dev") {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» — ветка разработки: её содержимое меняется под тем же именем. "+
				"Укажите выпущенную версию", version)
	}
	return nil
}

// composerPackage — ответ Packagist v2 (/p2/{vendor}/{package}.json).
type composerPackage struct {
	Packages map[string][]struct {
		Version           string   `json:"version"`
		VersionNormalized string   `json:"version_normalized"`
		Time              string   `json:"time"`
		License           []string `json:"license"`
		Dist              struct {
			Type   string `json:"type"`
			URL    string `json:"url"`
			Shasum string `json:"shasum"`
		} `json:"dist"`
	} `json:"packages"`
}

func (p *PHP) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	url := fmt.Sprintf("%s/p2/%s.json", strings.TrimRight(p.BaseURL, "/"), ref.Name)
	var payload composerPackage
	if err := getJSON(ctx, p.HTTP, url, "application/json", &payload); err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf("%w: пакета %s нет в реестре Packagist",
				ErrNotFound, ref.DisplayName)
		}
		return Metadata{}, err
	}

	versions := payload.Packages[ref.Name]
	if len(versions) == 0 {
		// Ключ в ответе — каноничное имя пакета; при расхождении регистра
		// берём единственный список, который есть.
		for _, list := range payload.Packages {
			versions = list
			break
		}
	}
	for _, v := range versions {
		// Сравниваем по нормализованной версии: в ответе она бывает и «v6.4.2»,
		// и «6.4.2.0», и искать точное совпадение строки значит не находить
		// половину версий.
		if p.NormalizeVersion(v.Version) != ref.Version &&
			!strings.HasPrefix(v.VersionNormalized, ref.Version+".") &&
			v.VersionNormalized != ref.Version {
			continue
		}
		meta := Metadata{
			Name:        ref.Name,
			Version:     ref.Version,
			PublishedAt: parseTime(v.Time),
			ArtifactURL: v.Dist.URL,
			// Packagist отдаёт дистрибутив zip-ом, собранным из тега
			// репозитория; имя файла он не сообщает, поэтому собираем его сами.
			ArtifactFilename: fmt.Sprintf("%s-%s.zip",
				safeFilename(ref.Name), safeFilename(ref.RawVersion)),
		}
		if v.Dist.Shasum != "" {
			// Packagist называет поле shasum, а кладёт в него sha1 —
			// исторически, как и npm.
			meta.Checksum, meta.ChecksumAlgo = v.Dist.Shasum, "sha1"
		}
		if len(v.License) > 0 {
			meta.LicenseRaw = strings.Join(v.License, " OR ")
			meta.LicenseSPDX = NormalizeSPDX(v.License[0])
		}
		if meta.ArtifactURL == "" {
			return Metadata{}, fmt.Errorf(
				"реестр Packagist не сообщил ссылку на дистрибутив %s:%s — "+
					"у пакета есть только исходники в репозитории",
				ref.DisplayName, ref.RawVersion)
		}
		return meta, nil
	}
	return Metadata{}, fmt.Errorf("%w: версии %s пакета %s нет в реестре Packagist",
		ErrNotFound, ref.RawVersion, ref.DisplayName)
}

func (p *PHP) InstallCommand(ref Ref, baseURL, repo string) string {
	source := fmt.Sprintf("%s/repository/%s", strings.TrimRight(baseURL, "/"), repo)
	return fmt.Sprintf(
		"composer config repositories.internal composer %s && composer require %s:%s",
		source, ref.DisplayName, ref.RawVersion)
}

func (p *PHP) ArtifactPath(ref Ref, filename string) string {
	return fmt.Sprintf("%s/%s/%s", ref.Name, ref.Version, filename)
}
