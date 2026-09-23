package registry

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	luaRockNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	// Версия rock — «X.Y.Z-N», где N (revision) обязателен в имени файла.
	luaRockVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.]*-\d+$`)
)

// LuaRocks — плагин менеджера luarocks. Формат записи: rock@version-revision.
//
// Revision в версии обязателен и не является косметикой: имя файла rock'а
// содержит его целиком (luasocket-3.1.0-1.src.rock), и без него нечего
// скачивать. Просить у разработчика «3.1.0» и дописывать «-1» самим нельзя:
// ревизий у одной версии бывает несколько, и они содержат разное.
type LuaRocks struct {
	// BaseURL — сервер luarocks или внутреннее зеркало.
	BaseURL string
	HTTP    Doer
}

func (*LuaRocks) Code() string  { return "luarocks" }
func (*LuaRocks) Title() string { return "LuaRocks (Lua)" }

func (*LuaRocks) EntryFormat() string { return "rock@version-revision" }

// OSVEcosystem — у LuaRocks в OSV своей экосистемы нет. Пустая строка честнее
// выдуманного имени: шаг проверки уязвимостей отличает «в базе ничего не
// нашлось» от «эту экосистему база не покрывает».
func (*LuaRocks) OSVEcosystem() string { return "" }

func (*LuaRocks) NormalizeName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }
func (*LuaRocks) NormalizeVersion(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
func (*LuaRocks) DisplayName(name string) string   { return strings.TrimSpace(name) }

func (*LuaRocks) DependencyFiles() []string { return []string{"*.rockspec"} }

func (p *LuaRocks) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, "@")
	if idx < 0 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату luarocks. Ожидается: rock@version-revision "+
				"(например, luasocket@3.1.0-1)", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *LuaRocks) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Имя rock'а длиннее 512 символов")
	}
	if !luaRockNameRe.MatchString(name) {
		return invalidFormat(p.EntryFormat(),
			"Недопустимое имя rock'а: «%s» (буквы, цифры, «.», «-», «_»)", name)
	}
	return nil
}

func (p *LuaRocks) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Версия длиннее 128 символов")
	}
	if !luaRockVersionRe.MatchString(version) {
		return invalidFormat(p.EntryFormat(),
			"Версия «%s» не соответствует формату luarocks: нужна версия С РЕВИЗИЕЙ, "+
				"например 3.1.0-1. Ревизия входит в имя файла rock'а, без неё "+
				"скачивать нечего", version)
	}
	return nil
}

func (p *LuaRocks) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	base := strings.TrimRight(p.BaseURL, "/")
	filename := fmt.Sprintf("%s-%s.src.rock", ref.Name, ref.Version)

	// Rockspec — текстовый файл с описанием; по нему проверяется существование
	// версии и берётся лицензия. Формата JSON у luarocks нет, это Lua-таблица,
	// поэтому лицензию достаём разбором одного поля, а не полноценным парсером:
	// исполнять чужой Lua ради строчки лицензии мы не будем.
	rockspecURL := fmt.Sprintf("%s/%s-%s.rockspec", base, ref.Name, ref.Version)
	body, err := getBytes(ctx, p.HTTP, rockspecURL, "text/plain")
	if err != nil {
		if err == ErrNotFound {
			return Metadata{}, fmt.Errorf("%w: rock %s %s отсутствует в реестре luarocks",
				ErrNotFound, ref.DisplayName, ref.RawVersion)
		}
		return Metadata{}, err
	}

	meta := Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		ArtifactURL:      fmt.Sprintf("%s/%s", base, filename),
		ArtifactFilename: filename,
		// Дату публикации luarocks не отдаёт ни одним API. Карантин по такому
		// пакету будет пропущен с пометкой — это лучше, чем выдуманная дата,
		// по которой он молча считался бы пройденным.
	}
	if license := luaRockspecField(string(body), "license"); license != "" {
		meta.LicenseRaw = license
		meta.LicenseSPDX = NormalizeSPDX(license)
	}
	return meta, nil
}

// luaRockspecField достаёт строковое поле верхнего уровня из rockspec.
//
// Rockspec — это Lua-код, и полный его разбор означал бы исполнение чужого
// кода в воркере. Нам нужна одна строка описания, а не вычисленная таблица,
// поэтому берём её регулярным выражением. Не нашлось — поле останется пустым,
// и лицензию определит юрист; это штатный, а не ошибочный исход.
func luaRockspecField(source, field string) string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(field) + `\s*=\s*["']([^"']*)["']`)
	if m := re.FindStringSubmatch(source); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	// Поле бывает вложено в таблицу description = { license = "MIT" }.
	nested := regexp.MustCompile(`(?s)description\s*=\s*\{.*?` +
		regexp.QuoteMeta(field) + `\s*=\s*["']([^"']*)["']`)
	if m := nested.FindStringSubmatch(source); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func (p *LuaRocks) InstallCommand(ref Ref, baseURL, repo string) string {
	server := fmt.Sprintf("%s/repository/%s", strings.TrimRight(baseURL, "/"), repo)
	return fmt.Sprintf("luarocks install --server=%s %s %s", server, ref.DisplayName, ref.RawVersion)
}

func (p *LuaRocks) ArtifactPath(ref Ref, filename string) string {
	// Плоская раскладка: именно так устроен репозиторий luarocks, и клиент
	// ищет rock по имени файла в корне сервера, а не по дереву каталогов.
	return filename
}
