package registry

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"
)

var (
	goModuleRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~\-]*(\.[A-Za-z0-9._~\-]+)*(/[A-Za-z0-9._~\-]+)*$`)
	goVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+incompatible)?$`)
	goUpperRe   = regexp.MustCompile(`[A-Z]`)
	goLicenseRe = regexp.MustCompile(`(?is)<div[^>]*id=["']#?lic-\d+["'][^>]*>(.*?)</div>`)
	goHTMLTagRe = regexp.MustCompile(`(?s)<[^>]+>`)
)

// Go — плагин менеджера go. Формат записи: module@vX.Y.Z.
type Go struct {
	BaseURL    string
	LicenseURL string
	HTTP       Doer
}

func (*Go) Code() string         { return "go" }
func (*Go) Title() string        { return "Go modules" }
func (*Go) EntryFormat() string  { return "module@vX.Y.Z" }
// OSV в этом сервисе включён только для PyPI и npm: для них администратор
// публикует отдельные проверенные снапшоты. Остальные менеджеры проходят шаг
// как неприменимый, а не блокируются из-за отсутствующей базы.
func (*Go) OSVEcosystem() string { return "" }

// NormalizeName — в базе имя хранится в нижнем регистре ради уникальности
// сравнения; настоящий путь модуля (с регистром) живёт в DisplayName и именно
// он уходит в proxy.
func (*Go) NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (*Go) NormalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

func (*Go) DisplayName(name string) string { return strings.TrimSpace(name) }

// SplitEntry — по ПОСЛЕДНЕМУ «@»: путь модуля может содержать «@» в редких
// случаях, а версия — нет.
func (p *Go) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, "@")
	if idx < 0 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату go. Ожидается: module@vX.Y.Z "+
				"(например, github.com/gin-gonic/gin@v1.9.1)", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *Go) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя пакета длиннее 512 символов")
	}
	if !goModuleRe.MatchString(name) {
		return invalidFormat(p.EntryFormat(), "Недопустимый путь модуля go: «%s»", name)
	}
	return nil
}

func (p *Go) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	candidate := version
	if !strings.HasPrefix(candidate, "v") {
		candidate = "v" + candidate
	}
	if !goVersionRe.MatchString(candidate) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует формату go (например, v1.9.1, v2.0.0+incompatible)", version)
	}
	return nil
}

// EscapeModule — go module proxy требует, чтобы заглавные буквы кодировались
// как «!x»: иначе на регистронезависимой файловой системе модули
// github.com/Sirupsen/logrus и github.com/sirupsen/logrus столкнулись бы.
func EscapeModule(path string) string {
	return goUpperRe.ReplaceAllStringFunc(path, func(m string) string {
		return "!" + strings.ToLower(m)
	})
}

type goInfo struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
}

func (p *Go) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	module := EscapeModule(ref.DisplayName)
	version := EscapeModule(ref.Version)

	var info goInfo
	infoURL := fmt.Sprintf("%s/%s/@v/%s.info", p.BaseURL, module, version)
	if err := getJSON(ctx, p.HTTP, infoURL, "application/json", &info); err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf("%w: модуль %s@%s отсутствует в go module proxy",
				ErrNotFound, ref.DisplayName, ref.Version)
		}
		return Metadata{}, err
	}

	meta := Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		PublishedAt:      parseTime(info.Time),
		ArtifactURL:      fmt.Sprintf("%s/%s/@v/%s.zip", p.BaseURL, module, version),
		ArtifactFilename: ref.Version + ".zip",
	}
	// Go proxy не хранит сведения о лицензии. pkg.go.dev публикует их для
	// конкретной версии; ошибка этого дополнительного источника не должна
	// превращать существующий модуль в ошибку заявки.
	licenseURL := fmt.Sprintf("%s/%s@%s?tab=licenses",
		strings.TrimRight(p.LicenseURL, "/"), ref.DisplayName, ref.Version)
	if p.LicenseURL != "" {
		if body, err := getBytes(ctx, p.HTTP, licenseURL, "text/html"); err == nil {
			meta.LicenseRaw, meta.LicenseSPDX = goLicenses(body)
		}
	}

	// Хеш модуля берём отдельным запросом; его отсутствие не повод валить
	// шаг — sha256 скачанного артефакта считается в любом случае.
	if body, err := getBytes(ctx, p.HTTP, fmt.Sprintf("%s/%s/@v/%s.ziphash", p.BaseURL, module, version), ""); err == nil {
		if checksum := strings.TrimSpace(string(body)); checksum != "" {
			meta.Checksum, meta.ChecksumAlgo = checksum, "h1"
		}
	}
	return meta, nil
}

func goLicenses(body []byte) (raw, spdx string) {
	var candidates []string
	for _, match := range goLicenseRe.FindAllSubmatch(body, -1) {
		text := html.UnescapeString(goHTMLTagRe.ReplaceAllString(string(match[1]), ""))
		for _, candidate := range strings.Split(text, ",") {
			if candidate = strings.TrimSpace(candidate); candidate != "" {
				candidates = append(candidates, candidate)
			}
		}
	}
	return normalizeLicenseCandidates(candidates)
}

func (p *Go) InstallCommand(ref Ref, baseURL, repo string) string {
	proxy := fmt.Sprintf("%s/repository/%s", strings.TrimRight(baseURL, "/"), repo)
	return fmt.Sprintf("GOPROXY=%s GONOSUMDB=* GONOSUMCHECK=1 go get %s@%s",
		proxy, ref.DisplayName, ref.Version)
}

func (p *Go) ArtifactPath(ref Ref, filename string) string {
	return fmt.Sprintf("%s/@v/%s", EscapeModule(ref.DisplayName), filename)
}

// DependencyFiles — те же шаблоны, что в python-версии (managers/golang.py).
func (*Go) DependencyFiles() []string {
	return []string{"go.mod", "go.sum"}
}
