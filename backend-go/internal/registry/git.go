package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// gitRefRe — имя ветки, тега или полный коммит. Запрещаем то, что git и сам
// запретит, плюс всё, что похоже на аргумент командной строки.
var gitRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// Git — модерация git-репозитория целиком. Формат записи: <url>@<ref>.
//
// Предмет модерации — состояние репозитория на конкретной ревизии, и оно
// приводится к архиву, потому что дальше по конвейеру идут проверки над
// файлами: песочница получает архив, отчёты ссылаются на файлы, артефактори
// хранит файл.
//
// Ревизия обязана быть неподвижной. Ветка ею не является: «main» сегодня и
// «main» завтра — разное содержимое, и решение, принятое по одному, относилось
// бы к другому. Поэтому ветка принимается, но приводится к коммиту, на котором
// она стояла в момент проверки, и именно коммит попадает в базу как версия.
type Git struct {
	// Binary — исполняемый файл git. Пусто — берётся «git» из PATH.
	Binary string
	// Timeout — потолок на клонирование. Репозиторий бывает большим, но не
	// бесконечным; зависшее клонирование не должно держать поток воркера.
	Timeout time.Duration
	// WorkDir — где разворачивать клон. Пусто — временный каталог системы.
	WorkDir string
}

func (*Git) Code() string  { return "git" }
func (*Git) Title() string { return "Git-репозитории" }

func (*Git) EntryFormat() string { return "<url>@<ветка, тег или коммит>" }

// OSVEcosystem — репозиторий ни к какой экосистеме OSV не относится: пакетом
// он станет только после сборки. Пустая строка честнее выдуманного имени.
func (*Git) OSVEcosystem() string { return "" }

// NormalizeName — адрес репозитория без завершающего «.git» и слеша: один и
// тот же репозиторий пишут и так, и так, а модерировать его дважды незачем.
func (*Git) NormalizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "/")
	return strings.TrimSuffix(name, ".git")
}

func (*Git) NormalizeVersion(version string) string { return strings.TrimSpace(version) }

func (*Git) DisplayName(name string) string { return strings.TrimSpace(name) }

func (*Git) DependencyFiles() []string { return nil }

func (p *Git) SplitEntry(entry string) (string, string, error) {
	text := strings.TrimSpace(entry)
	idx := strings.LastIndex(text, "@")
	// «@» встречается и в scp-подобном адресе (git@host:org/repo.git), поэтому
	// ищем последнее вхождение и проверяем, что справа не адрес.
	if idx < 0 || strings.ContainsAny(text[idx+1:], ":/") && strings.Contains(text[idx+1:], ".") {
		return "", "", invalidFormat(p.EntryFormat(),
			"«%s» не соответствует формату git. Ожидается: <url>@<ветка, тег или коммит> "+
				"(например, https://github.com/org/repo@v1.2.3)", text)
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func (p *Git) ValidateName(name string) error {
	if len(name) > 512 {
		return invalidFormat(p.EntryFormat(), "Адрес репозитория длиннее 512 символов")
	}
	parsed, err := url.Parse(name)
	if err != nil {
		return invalidFormat(p.EntryFormat(), "Адрес «%s» не разбирается: %v", name, err)
	}
	// Только http/https. ssh потребовал бы ключей у сервиса, а file:// читал бы
	// диск воркера — промодерирован был бы не тот репозиторий.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return invalidFormat(p.EntryFormat(),
			"Адрес должен быть http или https, а не «%s». Адреса вида git@host:org/repo "+
				"не поддерживаются: сервису негде взять ключ доступа", parsed.Scheme)
	}
	if parsed.Host == "" {
		return invalidFormat(p.EntryFormat(), "В адресе «%s» не указан сервер", name)
	}
	return nil
}

func (p *Git) ValidateVersion(version string) error {
	if len(version) > 128 {
		return invalidFormat(p.EntryFormat(), "Ревизия длиннее 128 символов")
	}
	if !gitRefRe.MatchString(version) {
		return invalidFormat(p.EntryFormat(),
			"Ревизия «%s» недопустима: ожидается имя ветки, тега или коммит "+
				"(буквы, цифры, «.», «-», «_», «/»)", version)
	}
	return nil
}

// FetchMetadata приводит ветку или тег к коммиту, не клонируя репозиторий.
//
// `git ls-remote` возвращает список ссылок — этого достаточно, чтобы узнать
// коммит и заодно убедиться, что репозиторий доступен, до того как конвейер
// дойдёт до скачивания.
func (p *Git) FetchMetadata(ctx context.Context, ref Ref) (Metadata, error) {
	repo := ref.DisplayName
	meta := Metadata{
		Name:    ref.Name,
		Version: ref.Version,
		// ArtifactURL пустой намеренно: скачивание идёт через Download, а не
		// одним GET. Шаг скачивания выбирает путь по наличию Downloader, а не
		// по этому полю.
		ArtifactFilename: fmt.Sprintf("%s-%s.tar.gz",
			safeFilename(repoShortName(ref.Name)), safeFilename(ref.RawVersion)),
		// Даты публикации у ревизии нет в том смысле, в каком она есть у
		// версии пакета: дата коммита — это когда его написали, а не когда
		// опубликовали. Карантин по репозиториям пропускается с пометкой.
	}

	// Полный коммит указывать можно, и тогда приводить нечего.
	if isFullCommit(ref.Version) {
		return meta, nil
	}

	out, err := p.run(ctx, "", "ls-remote", "--", repo, ref.Version)
	if err != nil {
		return Metadata{}, err
	}
	commit := firstToken(string(out))
	if commit == "" {
		return Metadata{}, fmt.Errorf(
			"%w: в репозитории %s нет ветки, тега или коммита «%s»",
			ErrNotFound, repo, ref.RawVersion)
	}
	// Коммит кладём в контрольную сумму, а не подменяем им версию: версия —
	// это то, что написал разработчик, и она обязана остаться узнаваемой в
	// карточке. А вот в отчёте и в базе должно быть видно, какому коммиту
	// соответствует промодерированный архив.
	meta.Checksum, meta.ChecksumAlgo = commit, "git-commit"
	return meta, nil
}

// Download клонирует репозиторий на нужной ревизии и упаковывает рабочее
// дерево в tar.gz.
//
// Каталог .git в архив не попадает: модерации подлежит содержимое на ревизии,
// а история — это ещё сотни ревизий, которых никто не заказывал, и вес, в
// разы больший самого содержимого.
func (p *Git) Download(ctx context.Context, ref Ref, limit int64) ([]byte, string, error) {
	filename := fmt.Sprintf("%s-%s.tar.gz",
		safeFilename(repoShortName(ref.Name)), safeFilename(ref.RawVersion))

	dir, err := os.MkdirTemp(p.WorkDir, "moderation-git-")
	if err != nil {
		return nil, "", fmt.Errorf("временный каталог для клонирования: %w", err)
	}
	defer os.RemoveAll(dir)

	checkout := filepath.Join(dir, "repo")
	// --depth 1 на конкретной ревизии: история не нужна, а её скачивание для
	// крупного репозитория занимает минуты и гигабайты.
	if _, err := p.run(ctx, "", "clone", "--depth", "1", "--branch", ref.RawVersion,
		"--single-branch", "--no-tags", "--", ref.DisplayName, checkout); err != nil {
		// --branch не принимает коммит. Для коммита нужен другой порядок:
		// пустой клон, затем fetch ровно этой ревизии.
		if !isFullCommit(ref.RawVersion) {
			return nil, "", err
		}
		if err := p.fetchCommit(ctx, checkout, ref); err != nil {
			return nil, "", err
		}
	}

	// .git убираем до упаковки, а не фильтруем при обходе: так исключено, что
	// часть истории просочится в архив через незамеченный путь.
	if err := os.RemoveAll(filepath.Join(checkout, ".git")); err != nil {
		return nil, "", fmt.Errorf("удаление служебного каталога .git: %w", err)
	}

	payload, err := tarGzDir(checkout, limit)
	if err != nil {
		return nil, "", err
	}
	return payload, filename, nil
}

// fetchCommit достаёт ровно одну ревизию по её хешу.
func (p *Git) fetchCommit(ctx context.Context, checkout string, ref Ref) error {
	if err := os.MkdirAll(checkout, 0o750); err != nil {
		return fmt.Errorf("каталог клона: %w", err)
	}
	steps := [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", "--", ref.DisplayName},
		{"fetch", "--depth", "1", "--quiet", "origin", ref.RawVersion},
		{"checkout", "--quiet", "FETCH_HEAD"},
	}
	for _, args := range steps {
		if _, err := p.run(ctx, checkout, args...); err != nil {
			return err
		}
	}
	return nil
}

// run выполняет git. Ошибку собираем с текстом stderr: «exit status 128» не
// говорит ничего, а «Repository not found» говорит всё.
func (p *Git) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	binary := p.Binary
	if binary == "" {
		binary = "git"
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binary, args...)
	cmd.Dir = dir
	// Терминал у команды отсутствует, и без этого git на закрытом репозитории
	// повиснет, ожидая ввода логина, пока не сработает таймаут.
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=echo",
		"GCM_INTERACTIVE=never",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}

	detail := strings.TrimSpace(stderr.String())
	if len(detail) > 500 {
		detail = detail[:500] + "…"
	}
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("git не уложился в %s: %s", timeout, detail)
	case errors.Is(err, exec.ErrNotFound):
		return nil, fmt.Errorf(
			"git не установлен в образе сервиса (искали «%s»): модерация репозиториев "+
				"без него невозможна", binary)
	}
	if detail == "" {
		detail = err.Error()
	}
	return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), detail)
}

// isFullCommit — полный sha1-хеш коммита (40 символов). Сокращённый не
// принимаем: он неоднозначен, и «тот же» коммит может оказаться другим.
func isFullCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// repoShortName — «repo» из «https://github.com/org/repo».
func repoShortName(name string) string {
	name = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(name), "/"), ".git")
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

func (p *Git) InstallCommand(ref Ref, baseURL, repo string) string {
	return fmt.Sprintf("curl -fLO %s/repository/%s/%s",
		strings.TrimRight(baseURL, "/"), repo,
		p.ArtifactPath(ref, fmt.Sprintf("%s-%s.tar.gz",
			safeFilename(repoShortName(ref.Name)), safeFilename(ref.RawVersion))))
}

func (p *Git) ArtifactPath(ref Ref, filename string) string {
	// Хост и путь репозитория сохраняем в раскладке: два репозитория с именем
	// «utils» на разных серверах — разные вещи, и складывать их в один каталог
	// нельзя.
	slug := safeFilename(strings.TrimPrefix(strings.TrimPrefix(ref.Name, "https://"), "http://"))
	return fmt.Sprintf("%s/%s/%s", slug, safeFilename(ref.RawVersion), filename)
}

var _ Downloader = (*Git)(nil)
