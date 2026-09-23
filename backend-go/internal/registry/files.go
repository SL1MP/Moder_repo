package registry

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var sha256Re = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Files — модерация готового файла: архива, бинаря, установщика — всего, что
// разработчик приносит сам. Формат записи: <url>@sha256:<хеш>.
//
// Соответствует менеджеру «general» CI-версии. Реестра у такого файла нет, и
// это определяет всё устройство плагина:
//
//   - версии в привычном смысле нет, поэтому версией служит sha256. Это не
//     уловка ради схемы: именно хеш отвечает на вопрос «те ли это байты, по
//     которым принято решение», а никакой другой признак на него не отвечает.
//     Перезалитый по тому же адресу файл получит другой хеш и придёт на
//     модерацию заново — как и должен;
//   - хеш обязателен и указывается ЗАРАНЕЕ. Посчитать его по скачанному файлу
//     и записать как «версию» значило бы модерировать что угодно, что лежало
//     по ссылке в момент скачивания;
//   - дата публикации неизвестна, поэтому карантин по таким файлам
//     пропускается с пометкой. Врать нулевой датой нельзя: карантин молча
//     считался бы пройденным.
type Files struct{}

func (*Files) Code() string  { return "files" }
func (*Files) Title() string { return "Файлы (архивы, бинарники)" }

func (*Files) EntryFormat() string { return "<url>@sha256:<хеш>" }

// OSVEcosystem — произвольный файл ни к какой экосистеме OSV не относится.
// Пустая строка честнее выдуманного имени: шаг уязвимостей отличит «в базе
// ничего не нашлось» от «эту экосистему база не покрывает».
func (*Files) OSVEcosystem() string { return "" }

// NormalizeName — URL целиком. Регистр схемы и хоста не значим, пути — значим,
// поэтому целиком в нижний регистр приводить нельзя: на многих серверах
// /File.zip и /file.zip это разные файлы.
func (*Files) NormalizeName(name string) string { return strings.TrimSpace(name) }

func (*Files) NormalizeVersion(version string) string {
	return strings.ToLower(strings.TrimSpace(version))
}

func (*Files) DisplayName(name string) string { return strings.TrimSpace(name) }

// DependencyFiles — файла зависимостей у этого менеджера нет и быть не может.
func (*Files) DependencyFiles() []string { return nil }

func (p *Files) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, "@sha256:")
	if idx < 0 {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату files. Ожидается: <url>@sha256:<хеш> "+
				"(например, https://example.com/tool.tar.gz@sha256:9f86d0…). "+
				"Хеш обязателен: он и есть версия — по нему видно, что байты те самые", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *Files) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Ссылка длиннее 512 символов")
	}
	parsed, err := url.Parse(name)
	if err != nil {
		return invalidFormat(p.EntryFormat(), "Ссылка «%s» не разбирается: %v", name, err)
	}
	// Только http/https: file:// прочитал бы файл с диска воркера, а не
	// принесённый разработчиком, и промодерирован был бы не тот файл.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return invalidFormat(p.EntryFormat(),
			"Ссылка должна быть http или https, а не «%s»", parsed.Scheme)
	}
	if parsed.Host == "" {
		return invalidFormat(p.EntryFormat(), "В ссылке «%s» не указан адрес сервера", name)
	}
	return nil
}

func (p *Files) ValidateVersion(version string) error {
	if !sha256Re.MatchString(strings.ToLower(strings.TrimSpace(version))) {
		return invalidFormat(p.EntryFormat(),
			"«%s» не похоже на sha256: ожидается sha256: и 64 шестнадцатеричных символа. "+
				"Посчитать можно так: sha256sum <файл>", version)
	}
	return nil
}

func (p *Files) FetchMetadata(_ context.Context, ref Ref) (Metadata, error) {
	// Наружу за метаданными не ходим: их неоткуда взять, а сам файл скачает
	// шаг скачивания. Контрольная сумма при этом заявлена — и шаг сверит её
	// ДО записи в промежуточную зону, то есть ровно так же, как для пакета из
	// реестра.
	filename := fileNameFromURL(ref.Name)
	return Metadata{
		Name:             ref.Name,
		Version:          ref.Version,
		ArtifactURL:      ref.DisplayName,
		ArtifactFilename: filename,
		Checksum:         strings.TrimPrefix(strings.ToLower(ref.Version), "sha256:"),
		ChecksumAlgo:     "sha256",
	}, nil
}

// fileNameFromURL — имя файла из ссылки. Запасной вариант нужен: ссылка вида
// https://host/download?id=42 имени файла не содержит вовсе.
func fileNameFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil {
		if base := path.Base(parsed.Path); base != "" && base != "." && base != "/" {
			return safeFilename(base)
		}
		if parsed.Host != "" {
			return safeFilename(parsed.Host) + ".bin"
		}
	}
	return "artifact.bin"
}

func (p *Files) InstallCommand(ref Ref, baseURL, repo string) string {
	return fmt.Sprintf("curl -fLO %s/repository/%s/%s",
		strings.TrimRight(baseURL, "/"), repo, p.ArtifactPath(ref, fileNameFromURL(ref.Name)))
}

func (p *Files) ArtifactPath(ref Ref, filename string) string {
	// Каталогом служит короткий префикс хеша: имена файлов у разных ссылок
	// совпадают сплошь и рядом (setup.exe, tool.tar.gz), а версии-хеша хватает,
	// чтобы они не затирали друг друга.
	digest := strings.TrimPrefix(strings.ToLower(ref.Version), "sha256:")
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return fmt.Sprintf("%s/%s", digest, filename)
}
