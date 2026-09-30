package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

var pypiNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// PyPI — плагин менеджера pypi. Формат записи: name==version.
type PyPI struct {
	BaseURL string
	HTTP    Doer
}

func (*PyPI) Code() string         { return "pypi" }
func (*PyPI) Title() string        { return "PyPI (Python)" }
func (*PyPI) EntryFormat() string  { return "name==version" }
func (*PyPI) OSVEcosystem() string { return "PyPI" }

// NormalizeName — PEP 503: регистр не важен, разделители эквивалентны.
func (*PyPI) NormalizeName(name string) string {
	return strings.ToLower(pypiSeparators.ReplaceAllString(strings.TrimSpace(name), "-"))
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// NormalizeVersion — полноценная нормализация PEP 440 (1.0 == 1.0.0 == 1.0.0.0)
// в Go потребовала бы отдельного компаратора и здесь сознательно не сделана:
// версия приводится к нижнему регистру без пробелов, а сверка эквивалентных
// записей — задача компаратора версий, который переносится вместе с разбором
// файлов зависимостей. Для конвейера этого достаточно: версия приходит из
// заявки и уходит в реестр как есть.
func (*PyPI) NormalizeVersion(version string) string {
	return strings.ToLower(strings.TrimSpace(version))
}

func (*PyPI) DisplayName(name string) string { return strings.TrimSpace(name) }

func (p *PyPI) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	name, version, found := strings.Cut(text, "==")
	if !found {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату pypi. Ожидается: name==version "+
				"(например, requests==2.31.0)", text)
	}
	return strings.TrimSpace(name), strings.TrimSpace(version), nil
}

func (p *PyPI) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя пакета длиннее 512 символов")
	}
	if !pypiNameRe.MatchString(name) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимое имя пакета pypi: «%s» (PEP 503: буквы, цифры, «-», «_», «.»)", name)
	}
	return nil
}

var pypiVersionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*((a|b|rc|alpha|beta|post|dev)\.?[0-9]*)*(\.post[0-9]+)?(\.dev[0-9]+)?(\+[A-Za-z0-9.]+)?$`)

func (p *PyPI) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	if !pypiVersionRe.MatchString(strings.ToLower(strings.TrimSpace(version))) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует PEP 440 (например, 2.31.0, 1.0.0rc1)", version)
	}
	return nil
}

// pypiResponse — та часть ответа /pypi/{name}/{version}/json, что нам нужна.
type pypiResponse struct {
	Info struct {
		License           string   `json:"license"`
		LicenseExpression string   `json:"license_expression"`
		Classifiers       []string `json:"classifiers"`
		Yanked            bool     `json:"yanked"`
	} `json:"info"`
	URLs []pypiDist `json:"urls"`
}

type pypiDist struct {
	PackageType       string            `json:"packagetype"`
	PythonVersion     string            `json:"python_version"`
	URL               string            `json:"url"`
	Filename          string            `json:"filename"`
	Size              int64             `json:"size"`
	Yanked            bool              `json:"yanked"`
	UploadTime        string            `json:"upload_time"`
	UploadTimeISO8601 string            `json:"upload_time_iso_8601"`
	Digests           map[string]string `json:"digests"`
}

func (p *PyPI) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	payload, err := p.release(ctx, ref)
	if err != nil {
		return Metadata{}, err
	}

	chosen := choosePypiDist(payload.URLs)
	meta := Metadata{Name: ref.Name, Version: ref.RawVersion}

	if chosen != nil {
		meta.PublishedAt = parseTime(chosen.UploadTimeISO8601)
		if meta.PublishedAt == nil {
			meta.PublishedAt = parseTime(chosen.UploadTime)
		}
		meta.ArtifactURL = chosen.URL
		meta.ArtifactFilename = chosen.Filename
		meta.SizeBytes = chosen.Size
		meta.Yanked = chosen.Yanked
		if sha := chosen.Digests["sha256"]; sha != "" {
			meta.Checksum, meta.ChecksumAlgo = sha, "sha256"
		}
	}
	// Дата публикации любой дистрибуции годится: карантин считается по версии,
	// а не по конкретному файлу.
	if meta.PublishedAt == nil {
		for i := range payload.URLs {
			if t := parseTime(payload.URLs[i].UploadTimeISO8601); t != nil {
				meta.PublishedAt = t
				break
			}
			if t := parseTime(payload.URLs[i].UploadTime); t != nil {
				meta.PublishedAt = t
				break
			}
		}
	}
	meta.Yanked = meta.Yanked || payload.Info.Yanked

	meta.LicenseRaw = strings.TrimSpace(payload.Info.License)
	meta.LicenseSPDX = NormalizeSPDX(payload.Info.LicenseExpression)
	if meta.LicenseSPDX == "" {
		meta.LicenseSPDX = NormalizeSPDX(meta.LicenseRaw)
	}
	if meta.LicenseSPDX == "" {
		meta.LicenseSPDX = SPDXFromClassifiers(payload.Info.Classifiers)
	}
	return meta, nil
}

func (p *PyPI) release(ctx context.Context, ref Ref) (pypiResponse, error) {
	requestURL := fmt.Sprintf("%s/pypi/%s/%s/json", p.BaseURL, ref.Name, ref.RawVersion)
	var payload pypiResponse
	if err := getJSON(ctx, p.HTTP, requestURL, "application/json", &payload); err != nil {
		if err == ErrNotFound {
			return pypiResponse{}, fmt.Errorf("%w: пакет %s==%s отсутствует в реестре pypi",
				ErrNotFound, ref.DisplayName, ref.RawVersion)
		}
		return pypiResponse{}, err
	}
	return payload, nil
}

func (*PyPI) ReleaseBundle() {}

// Download переносит весь релиз: source distribution и каждый wheel для всех
// опубликованных Python ABI/платформ. Выбор одного универсального wheel делал
// версию недоступной для разработчиков на другой платформе.
func (p *PyPI) Download(ctx context.Context, ref Ref, limit int64) ([]byte, string, error) {
	payload, err := p.release(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	dists := make([]pypiDist, 0, len(payload.URLs))
	seen := map[string]bool{}
	for _, dist := range payload.URLs {
		if dist.PackageType != "bdist_wheel" && dist.PackageType != "sdist" {
			continue
		}
		name := path.Base(strings.TrimSpace(dist.Filename))
		if name == "." || name == "" || name != dist.Filename || seen[name] {
			continue
		}
		seen[name] = true
		dists = append(dists, dist)
	}
	if len(dists) == 0 {
		return nil, "", fmt.Errorf("релиз %s==%s не содержит wheel или sdist",
			ref.DisplayName, ref.RawVersion)
	}
	sort.Slice(dists, func(i, j int) bool { return dists[i].Filename < dists[j].Filename })

	files := make([]BundleFile, 0, len(dists))
	remaining := limit
	for _, dist := range dists {
		if limit > 0 && (remaining <= 0 || dist.Size > remaining) {
			return nil, "", fmt.Errorf("файлы PyPI-релиза больше допустимого предела %d байт", limit)
		}
		body, err := getBytesWithLimit(ctx, p.HTTP, dist.URL, "application/octet-stream", remaining)
		if err != nil {
			return nil, "", fmt.Errorf("скачивание PyPI-файла %s: %w", dist.Filename, err)
		}
		if declared := strings.TrimSpace(dist.Digests["sha256"]); declared != "" {
			sum := sha256.Sum256(body)
			actual := hex.EncodeToString(sum[:])
			if !strings.EqualFold(actual, declared) {
				return nil, "", fmt.Errorf("sha256 PyPI-файла %s не совпал: ожидалось %s, получено %s",
					dist.Filename, declared, actual)
			}
		}
		files = append(files, BundleFile{Name: dist.Filename, Data: body})
		if limit > 0 {
			remaining -= int64(len(body))
		}
	}
	bundle, err := PackBundle("pypi", files, limit)
	if err != nil {
		return nil, "", err
	}
	filename := fmt.Sprintf("%s-%s.pypi-release.tgz", safeFilename(ref.Name), safeFilename(ref.RawVersion))
	return bundle, filename, nil
}

// choosePypiDist предпочитает wheel: он же обычно и публикуется во внутренний
// репозиторий.
func choosePypiDist(urls []pypiDist) *pypiDist {
	var wheels, sdists []*pypiDist
	for i := range urls {
		switch urls[i].PackageType {
		case "bdist_wheel":
			wheels = append(wheels, &urls[i])
		case "sdist":
			sdists = append(sdists, &urls[i])
		}
	}
	for _, w := range wheels {
		if strings.Contains(w.PythonVersion, "py3") {
			return w
		}
	}
	if len(wheels) > 0 {
		return wheels[0]
	}
	if len(sdists) > 0 {
		return sdists[0]
	}
	if len(urls) > 0 {
		return &urls[0]
	}
	return nil
}

func (p *PyPI) InstallCommand(ref Ref, baseURL, repo string) string {
	index := fmt.Sprintf("%s/repository/%s/simple", strings.TrimRight(baseURL, "/"), repo)
	return fmt.Sprintf("pip install -i %s %s==%s", index, ref.DisplayName, ref.RawVersion)
}

func (p *PyPI) ArtifactPath(ref Ref, filename string) string {
	return fmt.Sprintf("%s/%s/%s", ref.Name, ref.RawVersion, filename)
}

// DependencyFiles — те же шаблоны, что в python-версии (managers/pypi.py).
func (*PyPI) DependencyFiles() []string {
	return []string{"requirements*.txt", "poetry.lock", "pyproject.toml"}
}
