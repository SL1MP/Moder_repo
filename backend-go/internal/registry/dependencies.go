// Зависимости версии по данным реестра. Отсюда берётся граф, который
// раскрывает internal/resolve: что пакет объявил своими зависимостями и какие
// версии этих зависимостей вообще существуют.
package registry

import (
	"context"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"moderation/internal/depfile"
	"moderation/internal/version"
)

// Requirement — объявленная зависимость: имя и требование к версии в
// синтаксисе своей экосистемы. Версия здесь ещё диапазон, не выбор:
// выбирает internal/version по правилам менеджера.
type Requirement struct {
	Name       string
	Constraint string
	// Optional — зависимость ставится не всегда: extras у pypi,
	// optionalDependencies у npm. По умолчанию такие не раскрываются: их нет
	// в обычной установке, и тянуть их на модерацию значит звать людей
	// смотреть то, что никто не поставит.
	Optional bool
	// Note — почему требование особенное (например, условие окружения).
	Note string
}

// DependencyResolver — плагин умеет рассказать о зависимостях версии.
// Отдельный интерфейс, а не часть Plugin: не у всех менеджеров есть единый
// переносимый граф (например, Docker и general), а для Maven, PHP, Terraform
// и LuaRocks разрешение ещё не реализовано. Заглушка, молча возвращающая
// пустой список, была бы хуже честного «этот менеджер так не умеет».
type DependencyResolver interface {
	// Requirements — прямые зависимости версии, как их объявил сам пакет.
	Requirements(ctx context.Context, ref Ref) ([]Requirement, error)
	// Versions — версии пакета в реестре, из которых выбирается подходящая.
	Versions(ctx context.Context, name string) ([]string, error)
}

// ---------------------------------------------------------------- pypi

// pep508Re разбирает строку requires_dist: имя, extras, спецификатор версии,
// маркер окружения. Полный PEP 508 умеет больше (URL-зависимости, скобки в
// маркерах), но в requires_dist встречается именно эта форма.
var pep508Re = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*?)\s*(?:;\s*(.*))?$`)

// extraMarkerRe — маркер «зависимость только для extra». Такие требования
// объявлены под необязательный набор возможностей пакета.
var extraMarkerRe = regexp.MustCompile(`\bextra\s*==`)

// ParseRequiresDist разбирает одну строку requires_dist.
func ParseRequiresDist(line string) (Requirement, error) {
	text := strings.TrimSpace(line)
	if text == "" {
		return Requirement{}, fmt.Errorf("пустая строка зависимости")
	}
	m := pep508Re.FindStringSubmatch(text)
	if m == nil {
		return Requirement{}, fmt.Errorf("строка «%s» не разобрана как зависимость PEP 508", line)
	}
	req := Requirement{Name: m[1]}
	// Спецификатор в requires_dist приходит в скобках: «idna (<4,>=2.5)».
	constraint := strings.TrimSpace(m[3])
	constraint = strings.TrimPrefix(constraint, "(")
	constraint = strings.TrimSuffix(constraint, ")")
	req.Constraint = strings.TrimSpace(constraint)

	if marker := strings.TrimSpace(m[4]); marker != "" {
		if extraMarkerRe.MatchString(marker) {
			req.Optional = true
			req.Note = "объявлена под extra: " + marker
		} else {
			// Маркеры окружения (python_version, sys_platform) не
			// вычисляются: окружения установки у сервиса нет, а промодерировать
			// лишний пакет дешевле, чем пропустить нужный.
			req.Note = "условие окружения: " + marker
		}
	}
	return req, nil
}

type pypiRequiresResponse struct {
	Info struct {
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
}

func (p *PyPI) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	url := fmt.Sprintf("%s/pypi/%s/%s/json", p.BaseURL, ref.Name, ref.RawVersion)
	var payload pypiRequiresResponse
	if err := getJSON(ctx, p.HTTP, url, "application/json", &payload); err != nil {
		return nil, err
	}
	out := make([]Requirement, 0, len(payload.Info.RequiresDist))
	for _, line := range payload.Info.RequiresDist {
		req, err := ParseRequiresDist(line)
		if err != nil {
			// Неразобранная строка не роняет раскрытие: у пакета может быть
			// одна экзотическая зависимость из двадцати обычных.
			out = append(out, Requirement{Name: strings.TrimSpace(line), Note: err.Error()})
			continue
		}
		out = append(out, req)
	}
	return out, nil
}

type pypiSimpleResponse struct {
	Versions []string `json:"versions"`
}

func (p *PyPI) Versions(ctx context.Context, name string) ([]string, error) {
	url := fmt.Sprintf("%s/simple/%s/", p.BaseURL, p.NormalizeName(name))
	var payload pypiSimpleResponse
	// Simple API в форме JSON (PEP 691) отдаёт только список версий — в
	// отличие от /pypi/{name}/json, где к нему приложены метаданные всех
	// релизов и ответ разрастается до десятков мегабайт.
	if err := getJSON(ctx, p.HTTP, url, "application/vnd.pypi.simple.v1+json", &payload); err != nil {
		return nil, err
	}
	return payload.Versions, nil
}

// ---------------------------------------------------------------- npm

type npmDepsResponse struct {
	Versions map[string]struct {
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	} `json:"versions"`
}

func (p *Npm) packument(ctx context.Context, name string) (npmDepsResponse, error) {
	url := fmt.Sprintf("%s/%s", p.BaseURL, strings.ReplaceAll(p.NormalizeName(name), "/", "%2f"))
	var payload npmDepsResponse
	// Сокращённый формат (install-v1): без README и истории публикаций.
	err := getJSON(ctx, p.HTTP, url, "application/vnd.npm.install-v1+json, */*", &payload)
	return payload, err
}

func (p *Npm) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	payload, err := p.packument(ctx, ref.Name)
	if err != nil {
		return nil, err
	}
	version, ok := payload.Versions[ref.RawVersion]
	if !ok {
		return nil, fmt.Errorf("%w: версия %s пакета %s отсутствует в реестре npm",
			ErrNotFound, ref.RawVersion, ref.DisplayName)
	}
	out := make([]Requirement, 0, len(version.Dependencies)+len(version.OptionalDependencies))
	for name, constraint := range version.Dependencies {
		out = append(out, Requirement{Name: name, Constraint: constraint})
	}
	for name, constraint := range version.OptionalDependencies {
		out = append(out, Requirement{Name: name, Constraint: constraint, Optional: true,
			Note: "optionalDependencies"})
	}
	// peerDependencies сознательно не берутся: их ставит не сам пакет, а тот,
	// кто его подключает, и у него они уже есть в своём package.json.
	return out, nil
}

func (p *Npm) Versions(ctx context.Context, name string) ([]string, error) {
	payload, err := p.packument(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(payload.Versions))
	for version := range payload.Versions {
		out = append(out, version)
	}
	return out, nil
}

// ---------------------------------------------------------------- go

func (p *Go) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.mod", p.BaseURL, EscapeModule(ref.DisplayName), EscapeModule(ref.Version))
	body, err := getBytes(ctx, p.HTTP, url, "")
	if err != nil {
		return nil, err
	}
	// go.mod разбирается тем же парсером, что и загруженный файл заявки:
	// формат один, и держать два разбора значит однажды починить только один.
	deps, err := depfile.Parse("go", "go.mod", body)
	if err != nil {
		return nil, err
	}
	out := make([]Requirement, 0, len(deps))
	for _, dep := range deps {
		req := Requirement{Name: dep.Name, Constraint: dep.Version}
		if dep.Kind == depfile.KindTransitive {
			// «// indirect» в go.mod — зависимость зависимости, поднятая MVS
			// в файл модуля. Она часть сборки, поэтому раскрывается, но
			// помечается, чтобы в карточке было видно происхождение.
			req.Note = "indirect в go.mod"
		}
		out = append(out, req)
	}
	return out, nil
}

func (p *Go) Versions(ctx context.Context, name string) ([]string, error) {
	url := fmt.Sprintf("%s/%s/@v/list", p.BaseURL, EscapeModule(name))
	body, err := getBytes(ctx, p.HTTP, url, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if version := strings.TrimSpace(line); version != "" {
			out = append(out, version)
		}
	}
	// Список пуст у модулей, которые прокси отдаёт только по прямому запросу
	// версии (например, без тегов). Это не ошибка: версия требования уже
	// точная, и схема go проверит её отдельным запросом метаданных.
	return out, nil
}

// ---------------------------------------------------------------- nuget

type nuspecDocument struct {
	Metadata struct {
		Dependencies struct {
			// Зависимости бывают и в группах по target framework, и списком
			// на верхнем уровне — в nuspec допустимы обе формы.
			Groups []struct {
				TargetFramework string `xml:"targetFramework,attr"`
				Dependencies    []struct {
					ID      string `xml:"id,attr"`
					Version string `xml:"version,attr"`
				} `xml:"dependency"`
			} `xml:"group"`
			Dependencies []struct {
				ID      string `xml:"id,attr"`
				Version string `xml:"version,attr"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"metadata"`
}

func (p *NuGet) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	id := strings.ToLower(ref.Name)
	version := strings.ToLower(ref.Version)
	url := fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s.nuspec", p.BaseURL, id, version, id)
	body, err := getBytes(ctx, p.HTTP, url, "")
	if err != nil {
		return nil, err
	}
	var doc nuspecDocument
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("nuspec пакета %s %s не разобран: %w", ref.DisplayName, ref.Version, err)
	}

	// Объединение по всем target framework, а не выбор одного: у сервиса нет
	// целевой платформы сборки, и отбросить группу значит не промодерировать
	// пакет, который у разработчика окажется в сборке. Одинаковые id с
	// разными диапазонами сводятся к одному требованию — с самым старшим
	// нижним порогом, чтобы выбранная версия подошла всем группам.
	seen := map[string]int{}
	var out []Requirement
	add := func(id, constraint, note string) {
		if id == "" {
			return
		}
		key := strings.ToLower(id)
		if idx, ok := seen[key]; ok {
			if nugetLowerBoundHigher(constraint, out[idx].Constraint) {
				out[idx].Constraint = constraint
			}
			return
		}
		seen[key] = len(out)
		out = append(out, Requirement{Name: id, Constraint: constraint, Note: note})
	}
	for _, group := range doc.Metadata.Dependencies.Groups {
		note := ""
		if group.TargetFramework != "" {
			note = "target framework: " + group.TargetFramework
		}
		for _, dep := range group.Dependencies {
			add(dep.ID, dep.Version, note)
		}
	}
	for _, dep := range doc.Metadata.Dependencies.Dependencies {
		add(dep.ID, dep.Version, "")
	}
	return out, nil
}

type nugetIndexResponse struct {
	Versions []string `json:"versions"`
}

func (p *NuGet) Versions(ctx context.Context, name string) ([]string, error) {
	url := fmt.Sprintf("%s/v3-flatcontainer/%s/index.json", p.BaseURL, strings.ToLower(p.NormalizeName(name)))
	var payload nugetIndexResponse
	if err := getJSON(ctx, p.HTTP, url, "application/json", &payload); err != nil {
		return nil, err
	}
	return payload.Versions, nil
}

// ensure — плагины действительно реализуют интерфейс. Проверка на этапе
// компиляции: иначе опечатка в сигнатуре превратилась бы в «менеджер не
// умеет раскрывать зависимости» в рантайме.
var (
	_ DependencyResolver = (*PyPI)(nil)
	_ DependencyResolver = (*Npm)(nil)
	_ DependencyResolver = (*Go)(nil)
	_ DependencyResolver = (*NuGet)(nil)
	_ DependencyResolver = (*Conan)(nil)
)

// nugetLowerBoundHigher — у требования a нижний порог выше, чем у b.
func nugetLowerBoundHigher(a, b string) bool {
	scheme := version.NuGet{}
	low, other := scheme.LowerBound(a), scheme.LowerBound(b)
	if low == "" {
		return false
	}
	if other == "" {
		return true
	}
	return scheme.Compare(low, other) > 0
}
