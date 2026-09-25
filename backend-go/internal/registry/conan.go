package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	conanNameRe               = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_+.-]*$`)
	conanVersionRe            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+.-]*$`)
	conanLicenseRe            = regexp.MustCompile(`(?m)^\s*license\s*=\s*([^\r\n#]+)`)
	conanRequiresAssignmentRe = regexp.MustCompile(`(?m)^\s*requires\s*=\s*([^\r\n#]+)`)
	conanRequiresCallRe       = regexp.MustCompile(`self\.(requires|tool_requires|test_requires)\s*\(\s*["']([^"']+)["']`)
	conanStringRe             = regexp.MustCompile(`["']([^"']+)["']`)
)

// Conan — плагин менеджера conan (C/C++). Формат записи: name/version.
//
// Модерируется РЕЦЕПТ, а не собранный бинарный пакет. Причина не в простоте:
// бинарных пакетов у одного рецепта десятки — по одному на комбинацию
// компилятора, архитектуры, типа сборки и опций (package_id), — и «пакет
// conan» без этой комбинации не определён. Рецепт же один, он и содержит то,
// ради чего модерация существует: ссылки на исходники, патчи и скрипт сборки.
//
// Вместе с рецептом скачивается conandata.yml, где лежат адреса, откуда
// рецепт тянет исходники: именно их и надо видеть при проверке.
type Conan struct {
	// BaseURL — сервер conan (ConanCenter или внутреннее зеркало).
	BaseURL string
	HTTP    Doer
}

func (*Conan) Code() string  { return "conan" }
func (*Conan) Title() string { return "Conan (C/C++)" }

func (*Conan) EntryFormat() string { return "name/version" }

// OSVEcosystem — своей экосистемы у Conan в OSV нет. Пустая строка честнее
// выдуманного имени: шаг уязвимостей отличит «в базе ничего не нашлось» от
// «эту экосистему база не покрывает».
func (*Conan) OSVEcosystem() string { return "" }

func (*Conan) NormalizeName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }
func (*Conan) NormalizeVersion(v string) string { return strings.TrimSpace(v) }
func (*Conan) DisplayName(name string) string   { return strings.TrimSpace(name) }

func (*Conan) DependencyFiles() []string {
	return []string{"conanfile.txt", "conanfile.py", "conan.lock"}
}

func (p *Conan) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	// Запись conan бывает с каналом: name/version@user/channel. Канал для
	// ConanCenter пустой («_/_»), и поддерживать его здесь не нужно — но
	// сказать об этом надо, иначе пользователь получит «неверный формат» без
	// объяснения, что именно лишнее.
	if idx := strings.Index(text, "@"); idx >= 0 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» содержит user/channel. Сервис модерирует рецепты из общего канала: "+
				"укажите просто name/version (например, zlib/1.3.1)", text)
	}
	parts := strings.Split(text, "/")
	if len(parts) != 2 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату conan. Ожидается: name/version "+
				"(например, zlib/1.3.1)", text)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

func (p *Conan) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя рецепта длиннее 512 символов")
	}
	if !conanNameRe.MatchString(name) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимое имя рецепта conan: «%s» (буквы, цифры, «.», «-», «_», «+»)", name)
	}
	return nil
}

func (p *Conan) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	if !conanVersionRe.MatchString(version) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует формату conan (например, 1.3.1)", version)
	}
	return nil
}

// conanRevisions — ответ /v2/conans/{ref}/revisions.
type conanRevisions struct {
	Revisions []struct {
		Revision string `json:"revision"`
		Time     string `json:"time"`
	} `json:"revisions"`
}

// conanFiles — ответ /v2/conans/{ref}/revisions/{rev}/files.
type conanFiles struct {
	Files map[string]struct{} `json:"files"`
}

type conanRecipeLocation struct {
	Revision    string
	PublishedAt *time.Time
	FilesURL    string
	ArchiveURL  string
	RecipeURL   string
	Files       []string
}

// recipePath — путь рецепта в API conan. Канал общий, поэтому «_/_».
func (p *Conan) recipePath(ref Ref) string {
	return fmt.Sprintf("v2/conans/%s/%s/_/_", ref.Name, ref.Version)
}

func (p *Conan) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	location, err := p.recipeLocation(ctx, ref)
	if err != nil {
		return Metadata{}, err
	}
	meta := Metadata{
		Name:        ref.Name,
		Version:     ref.Version,
		PublishedAt: location.PublishedAt,
		ArtifactURL: location.ArchiveURL,
		// Ревизия — в имени файла: по нему в артефактори видно, какое именно
		// содержимое промодерировано.
		ArtifactFilename: fmt.Sprintf("%s-%s-%s.conan-recipe.tgz",
			safeFilename(ref.Name), safeFilename(ref.RawVersion), shortRevision(location.Revision)),
	}
	// Рецепт — Python-код, но для метаданных его выполнять не нужно и опасно.
	// Читаем только статическое присваивание license с жёсткими ограничениями
	// размера. Если рецепт вычисляет поле динамически, пакет как и прежде уйдёт
	// юристу.
	if recipe, err := p.recipeSource(ctx, location); err == nil {
		meta.LicenseRaw, meta.LicenseSPDX = conanLicense(recipe)
	}
	return meta, nil
}

// recipeLocation находит последнюю воспроизводимую ревизию рецепта и архив.
func (p *Conan) recipeLocation(ctx context.Context, ref Ref) (conanRecipeLocation, error) {
	base := strings.TrimRight(p.BaseURL, "/")

	// Ревизия рецепта — то, что делает содержимое воспроизводимым: под одной
	// version у рецепта бывает несколько ревизий с разными патчами.
	var revisions conanRevisions
	if err := getJSON(ctx, p.HTTP,
		fmt.Sprintf("%s/%s/revisions", base, p.recipePath(ref)),
		"application/json", &revisions); err != nil {
		if err == ErrNotFound {
			return conanRecipeLocation{}, fmt.Errorf("%w: рецепта %s/%s нет в реестре conan",
				ErrNotFound, ref.DisplayName, ref.RawVersion)
		}
		return conanRecipeLocation{}, err
	}
	if len(revisions.Revisions) == 0 {
		return conanRecipeLocation{}, fmt.Errorf("%w: у рецепта %s/%s нет ни одной ревизии",
			ErrNotFound, ref.DisplayName, ref.RawVersion)
	}
	// Сортируем по времени: порядок в ответе сервера не гарантирован, а «взять
	// последний элемент» при неотсортированном ответе — это взять случайную
	// ревизию.
	sorted := revisions.Revisions
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Time < sorted[j].Time })
	latest := sorted[len(sorted)-1]

	filesURL := fmt.Sprintf("%s/%s/revisions/%s/files", base, p.recipePath(ref), latest.Revision)
	var files conanFiles
	if err := getJSON(ctx, p.HTTP, filesURL, "application/json", &files); err != nil {
		return conanRecipeLocation{}, err
	}
	// conan_export.tgz — сам рецепт со всеми вспомогательными файлами
	// (conandata.yml, патчи). Это и есть предмет модерации.
	const exportFile = "conan_export.tgz"
	if _, ok := files.Files[exportFile]; !ok {
		available := make([]string, 0, len(files.Files))
		for name := range files.Files {
			available = append(available, name)
		}
		sort.Strings(available)
		return conanRecipeLocation{}, fmt.Errorf(
			"в ревизии %s рецепта %s/%s нет файла %s — скачивать нечего (есть: %s)",
			latest.Revision, ref.DisplayName, ref.RawVersion, exportFile,
			strings.Join(available, ", "))
	}

	location := conanRecipeLocation{
		Revision: latest.Revision, PublishedAt: parseTime(latest.Time),
		FilesURL: filesURL, ArchiveURL: filesURL + "/" + exportFile,
	}
	for name := range files.Files {
		clean := path.Clean(name)
		if clean == name && path.Base(clean) == clean && clean != "." && clean != ".." {
			location.Files = append(location.Files, clean)
		}
	}
	sort.Strings(location.Files)
	// ConanCenter 2 хранит conanfile.py отдельным файлом ревизии. Некоторые
	// внутренние серверы оставляют его только внутри conan_export.tgz, поэтому
	// архив остаётся резервным источником.
	if _, ok := files.Files["conanfile.py"]; ok {
		location.RecipeURL = filesURL + "/conanfile.py"
	}
	return location, nil
}

// Download собирает полный снимок recipe revision, а не только
// conan_export.tgz. Нативному Conan-репозиторию нужны также conanfile.py,
// conanmanifest.txt, conandata.yml, conan_sources.tgz и служебные файлы,
// которые сообщил upstream. Внешний tar.gz нужен лишь как транспорт через
// единый конвейер; при публикации Nexus-адаптер распакует его и загрузит
// каждый файл по Conan v2 API.
func (p *Conan) Download(ctx context.Context, ref Ref, limit int64) ([]byte, string, error) {
	location, err := p.recipeLocation(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	if len(location.Files) == 0 || len(location.Files) > maxConanRecipeFiles {
		return nil, "", fmt.Errorf("некорректное число файлов Conan recipe: %d", len(location.Files))
	}

	var buf limitedBuffer
	buf.limit = limit
	var total int64
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range location.Files {
		remaining := limit - total
		if limit > 0 && remaining <= 0 {
			return nil, "", fmt.Errorf("файлы Conan recipe больше допустимого предела %d байт", limit)
		}
		body, err := getBytesWithLimit(
			ctx, p.HTTP, location.FilesURL+"/"+url.PathEscape(name), "", remaining,
		)
		if err != nil {
			return nil, "", fmt.Errorf("скачивание файла Conan recipe %s: %w", name, err)
		}
		total += int64(len(body))
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(header); err != nil {
			return nil, "", err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, "", err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	if err := gz.Close(); err != nil {
		return nil, "", err
	}
	if buf.err != nil {
		return nil, "", buf.err
	}
	filename := fmt.Sprintf("%s-%s-%s.conan-recipe.tgz",
		safeFilename(ref.Name), safeFilename(ref.RawVersion), shortRevision(location.Revision))
	return buf.data, filename, nil
}

const (
	maxConanRecipeFiles = 256
	maxConanFileBytes   = 2 * 1024 * 1024
)

// conanFileFromArchive извлекает только conanfile.py. Ни Python, ни хуки
// рецепта не запускаются; пути и размеры ограничены.
func conanFileFromArchive(body []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("архив рецепта conan не является gzip: %w", err)
	}
	defer gz.Close()
	t := tar.NewReader(gz)
	for files := 0; files < maxConanRecipeFiles; files++ {
		header, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("архив рецепта conan не разобран: %w", err)
		}
		if header.Typeflag != tar.TypeReg || path.Base(path.Clean(header.Name)) != "conanfile.py" {
			continue
		}
		if header.Size < 0 || header.Size > maxConanFileBytes {
			return nil, fmt.Errorf("conanfile.py слишком большой: %d байт", header.Size)
		}
		return io.ReadAll(io.LimitReader(t, maxConanFileBytes+1))
	}
	return nil, fmt.Errorf("в conan_export.tgz нет conanfile.py")
}

func (p *Conan) recipeSource(ctx context.Context, location conanRecipeLocation) ([]byte, error) {
	if location.RecipeURL != "" {
		if recipe, err := getBytes(ctx, p.HTTP, location.RecipeURL, "text/plain"); err == nil {
			if len(recipe) > maxConanFileBytes {
				return nil, fmt.Errorf("conanfile.py слишком большой: %d байт", len(recipe))
			}
			return recipe, nil
		}
	}
	archive, err := getBytes(ctx, p.HTTP, location.ArchiveURL, "application/gzip")
	if err != nil {
		return nil, err
	}
	return conanFileFromArchive(archive)
}

func conanLicense(recipe []byte) (raw, spdx string) {
	match := conanLicenseRe.FindSubmatch(recipe)
	if len(match) < 2 {
		return "", ""
	}
	var candidates []string
	for _, value := range conanStringRe.FindAllSubmatch(match[1], -1) {
		candidates = append(candidates, string(value[1]))
	}
	return normalizeLicenseCandidates(candidates)
}

// Requirements статически читает ссылки из conanfile.py. Это безопасный
// over-approximation: условия settings/options не исполняются, поэтому в
// дерево могут попасть зависимости другой платформы, но нужная зависимость
// не будет молча пропущена.
func (p *Conan) Requirements(ctx context.Context, ref Ref) ([]Requirement, error) {
	location, err := p.recipeLocation(ctx, ref)
	if err != nil {
		return nil, err
	}
	recipe, err := p.recipeSource(ctx, location)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Requirement
	add := func(reference, kind string) {
		name, constraint, ok := strings.Cut(strings.TrimSpace(reference), "/")
		if !ok || name == "" || constraint == "" || strings.ContainsAny(reference, "{}$") {
			return
		}
		constraint, _, _ = strings.Cut(constraint, "@")
		constraint, _, _ = strings.Cut(constraint, "#")
		key := strings.ToLower(name) + "\x00" + constraint
		if seen[key] {
			return
		}
		seen[key] = true
		note := "статически извлечено из conanfile.py; условия settings/options не вычислялись"
		if kind != "requires" {
			note = kind + "; " + note
		}
		out = append(out, Requirement{Name: name, Constraint: constraint, Note: note})
	}
	if assignment := conanRequiresAssignmentRe.FindSubmatch(recipe); len(assignment) > 1 {
		for _, value := range conanStringRe.FindAllSubmatch(assignment[1], -1) {
			add(string(value[1]), "requires")
		}
	}
	for _, call := range conanRequiresCallRe.FindAllSubmatch(recipe, -1) {
		add(string(call[2]), string(call[1]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Constraint < out[j].Constraint
	})
	return out, nil
}

type conanSearchResponse struct {
	Results []string `json:"results"`
}

func (p *Conan) Versions(ctx context.Context, name string) ([]string, error) {
	query := url.QueryEscape(p.NormalizeName(name) + "/*")
	var payload conanSearchResponse
	if err := getJSON(ctx, p.HTTP, strings.TrimRight(p.BaseURL, "/")+"/v2/conans/search?q="+query,
		"application/json", &payload); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var versions []string
	for _, reference := range payload.Results {
		reference, _, _ = strings.Cut(reference, "#")
		reference, _, _ = strings.Cut(reference, "@")
		foundName, version, ok := strings.Cut(reference, "/")
		if !ok || !strings.EqualFold(foundName, name) || version == "" || seen[version] {
			continue
		}
		seen[version] = true
		versions = append(versions, version)
	}
	return versions, nil
}

func shortRevision(revision string) string {
	if len(revision) > 12 {
		return revision[:12]
	}
	if revision == "" {
		return "norev"
	}
	return revision
}

func (p *Conan) InstallCommand(ref Ref, baseURL, repo string) string {
	remote := fmt.Sprintf("%s/repository/%s", strings.TrimRight(baseURL, "/"), repo)
	return fmt.Sprintf("conan remote add internal %s && conan install --requires=%s/%s -r internal",
		remote, ref.DisplayName, ref.RawVersion)
}

func (p *Conan) ArtifactPath(ref Ref, filename string) string {
	return fmt.Sprintf("%s/%s/%s", ref.Name, ref.Version, filename)
}
