package registry

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var npmNameRe = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

// Npm — плагин менеджера npm. Формат записи: [@scope/]name@version.
type Npm struct {
	BaseURL string
	HTTP    Doer
}

func (*Npm) Code() string         { return "npm" }
func (*Npm) Title() string        { return "npm (JavaScript)" }
func (*Npm) EntryFormat() string  { return "[@scope/]name@version" }
func (*Npm) OSVEcosystem() string { return "npm" }

func (*Npm) NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
func (*Npm) NormalizeVersion(version string) string { return strings.TrimSpace(version) }
func (*Npm) DisplayName(name string) string         { return strings.TrimSpace(name) }

// SplitEntry — «@» и разделитель имени и версии, и начало scope. Поэтому у
// scoped-пакета «@» в начале отрезается, и только потом ищется разделитель:
// иначе «@babel/core@7.24.0» разобралось бы как имя «» и версия «babel/...».
func (p *Npm) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	scoped := strings.HasPrefix(text, "@")
	body := text
	if scoped {
		body = text[1:]
	}
	name, version, found := strings.Cut(body, "@")
	if !found {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату npm. Ожидается: [@scope/]name@version "+
				"(например, lodash@4.17.21 или @babel/core@7.24.0)", text)
	}
	if scoped {
		name = "@" + name
	}
	return strings.TrimSpace(name), strings.TrimSpace(version), nil
}

func (p *Npm) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя пакета длиннее 512 символов")
	}
	if !npmNameRe.MatchString(strings.ToLower(name)) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимое имя пакета npm: «%s» (строчные буквы, цифры, «-», «_», «.», scope через «/»)", name)
	}
	return nil
}

var npmVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$`)

func (p *Npm) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	if !npmVersionRe.MatchString(strings.TrimSpace(version)) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует semver (например, 4.17.21, 7.0.0-beta.1)", version)
	}
	return nil
}

type npmResponse struct {
	Versions map[string]npmVersion `json:"versions"`
	Time     map[string]string     `json:"time"`
	License  json.RawMessage       `json:"license"`
	Licenses json.RawMessage       `json:"licenses"`
}

type npmVersion struct {
	License    json.RawMessage `json:"license"`
	Licenses   json.RawMessage `json:"licenses"`
	Deprecated string          `json:"deprecated"`
	Dist       struct {
		Tarball      string `json:"tarball"`
		Shasum       string `json:"shasum"`
		Integrity    string `json:"integrity"`
		UnpackedSize int64  `json:"unpackedSize"`
	} `json:"dist"`
}

func (p *Npm) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	// Scoped-имя в пути экранируется: «@babel/core» -> «@babel%2fcore».
	url := fmt.Sprintf("%s/%s", p.BaseURL, strings.ReplaceAll(ref.Name, "/", "%2f"))
	var payload npmResponse
	err := getJSON(ctx, p.HTTP, url, "application/vnd.npm.install-v1+json, */*", &payload)
	if err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf("%w: пакет %s@%s отсутствует в реестре npm",
				ErrNotFound, ref.DisplayName, ref.RawVersion)
		}
		return Metadata{}, err
	}

	version, ok := payload.Versions[ref.RawVersion]
	if !ok {
		// Пакет есть, версии нет — это тоже «не найдено», и сообщение должно
		// отличать этот случай: он чаще всего означает опечатку в версии.
		return Metadata{}, fmt.Errorf("%w: версия %s пакета %s отсутствует в реестре npm (версий в реестре: %d)",
			ErrNotFound, ref.RawVersion, ref.DisplayName, len(payload.Versions))
	}

	meta := Metadata{
		Name:        ref.Name,
		Version:     ref.RawVersion,
		PublishedAt: parseTime(payload.Time[ref.RawVersion]),
		ArtifactURL: version.Dist.Tarball,
		SizeBytes:   version.Dist.UnpackedSize,
		Yanked:      strings.TrimSpace(version.Deprecated) != "",
	}
	if meta.ArtifactURL != "" {
		parts := strings.Split(meta.ArtifactURL, "/")
		meta.ArtifactFilename = parts[len(parts)-1]
	}
	meta.Checksum, meta.ChecksumAlgo = npmChecksum(version.Dist.Integrity, version.Dist.Shasum)

	candidates := npmLicenseCandidates(version.License)
	candidates = append(candidates, npmLicenseCandidates(version.Licenses)...)
	if len(candidates) == 0 {
		candidates = append(candidates, npmLicenseCandidates(payload.License)...)
		candidates = append(candidates, npmLicenseCandidates(payload.Licenses)...)
	}
	meta.LicenseRaw, meta.LicenseSPDX = normalizeLicenseCandidates(candidates)
	return meta, nil
}

// npmLicenseCandidates разбирает все исторические формы npm: строку,
// объект {"type":"MIT"} и deprecated-массив licenses.
func npmLicenseCandidates(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if value := strings.TrimSpace(asString); value != "" {
			return []string{value}
		}
		return nil
	}
	var asObject struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		if value := strings.TrimSpace(asObject.Type); value != "" {
			return []string{value}
		}
		return nil
	}
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err != nil {
		return nil
	}
	var candidates []string
	for _, item := range asArray {
		candidates = append(candidates, npmLicenseCandidates(item)...)
	}
	return candidates
}

// npmChecksum — `integrity` (sha512 в base64) предпочтительнее устаревшего
// `shasum` (sha1).
func npmChecksum(integrity, shasum string) (string, string) {
	if algo, encoded, found := strings.Cut(integrity, "-"); found {
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			return hex.EncodeToString(decoded), algo
		}
	}
	if shasum != "" {
		return shasum, "sha1"
	}
	return "", ""
}

func (p *Npm) InstallCommand(ref Ref, baseURL, repo string) string {
	registry := fmt.Sprintf("%s/repository/%s/", strings.TrimRight(baseURL, "/"), repo)
	return fmt.Sprintf("npm i --registry=%s %s@%s", registry, ref.DisplayName, ref.RawVersion)
}

func (p *Npm) ArtifactPath(ref Ref, filename string) string {
	return fmt.Sprintf("%s/-/%s", ref.Name, filename)
}

// DependencyFiles — те же шаблоны, что в python-версии (managers/npm.py).
func (*Npm) DependencyFiles() []string {
	return []string{"package-lock.json", "yarn.lock", "package.json"}
}
