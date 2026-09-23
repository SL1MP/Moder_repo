package registry

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	conanNameRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_+.-]*$`)
	conanVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+.-]*$`)
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

// recipePath — путь рецепта в API conan. Канал общий, поэтому «_/_».
func (p *Conan) recipePath(ref Ref) string {
	return fmt.Sprintf("v2/conans/%s/%s/_/_", ref.Name, ref.Version)
}

func (p *Conan) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	base := strings.TrimRight(p.BaseURL, "/")

	// Ревизия рецепта — то, что делает содержимое воспроизводимым: под одной
	// version у рецепта бывает несколько ревизий с разными патчами. Берём
	// последнюю и фиксируем её в метаданных — без этого «zlib/1.3.1» через
	// месяц означал бы другое содержимое.
	var revisions conanRevisions
	if err := getJSON(ctx, p.HTTP,
		fmt.Sprintf("%s/%s/revisions", base, p.recipePath(ref)),
		"application/json", &revisions); err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf("%w: рецепта %s/%s нет в реестре conan",
				ErrNotFound, ref.DisplayName, ref.RawVersion)
		}
		return Metadata{}, err
	}
	if len(revisions.Revisions) == 0 {
		return Metadata{}, fmt.Errorf("%w: у рецепта %s/%s нет ни одной ревизии",
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
		return Metadata{}, err
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
		return Metadata{}, fmt.Errorf(
			"в ревизии %s рецепта %s/%s нет файла %s — скачивать нечего (есть: %s)",
			latest.Revision, ref.DisplayName, ref.RawVersion, exportFile,
			strings.Join(available, ", "))
	}

	return Metadata{
		Name:        ref.Name,
		Version:     ref.Version,
		PublishedAt: parseTime(latest.Time),
		ArtifactURL: filesURL + "/" + exportFile,
		// Ревизия — в имени файла: по нему в артефактори видно, какое именно
		// содержимое промодерировано.
		ArtifactFilename: fmt.Sprintf("%s-%s-%s.tgz",
			safeFilename(ref.Name), safeFilename(ref.RawVersion), shortRevision(latest.Revision)),
		// Лицензию conan отдаёт только внутри conanfile.py, то есть в коде
		// рецепта. Разбирать чужой Python ради строки лицензии мы не будем:
		// пакет уйдёт к юристу, и это честнее угаданного значения.
	}, nil
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
