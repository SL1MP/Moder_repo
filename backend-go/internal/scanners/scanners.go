// Package scanners — сканеры содержимого пакета: политические баннеры (YARA) и
// SAST (semgrep). Порт backend/app/adapters/content_scan.py.
//
// Оба работают по одной схеме: артефакт уже разложен во временный каталог
// (internal/unpack), сканер проходит по файлам и возвращает находки. Дальше
// решение принимает конвейер, а не сканер.
//
// Правило, общее для обоих и намеренно строгое: **недоступный сканер не значит
// «чисто»**. Если правила не подложены или бинаря нет, сканер возвращает
// Outcome с Available=false, а шаг конвейера отдаёт предупреждение и зовёт
// DevSecOps. Молча пропустить пакет мимо проверки нельзя — ровно так же
// устроен шаг с базой OSV.
//
// Отличие от Python-версии: там YARA вызывалась через модуль yara-python
// (cgo-биндинг к libyara), здесь — через тот же CLI-бинарь `yara`, что и
// semgrep через `semgrep`. Это осознанный выбор: биндинг тянет cgo и libyara в
// сборку Go-образа, а единообразный запуск двух внешних бинарей проще
// эксплуатировать и одинаково честно отчитывается о недоступности.
package scanners

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SeverityOrder — порядок серьёзности по возрастанию. Индекс в этом срезе
// используется для сравнения с порогом шага.
var SeverityOrder = []string{"info", "low", "medium", "high", "critical"}

// SeverityRank — место severity в SeverityOrder; неизвестное значение
// приравнивается к "medium", как в Python-версии для незнакомых уровней
// semgrep (не к "info": незнакомое не должно тихо проваливаться ниже порога).
func SeverityRank(severity string) int {
	for i, s := range SeverityOrder {
		if s == severity {
			return i
		}
	}
	return 2 // medium
}

// KnownSeverity — есть ли такое значение в шкале. Отличать «high» от значения,
// которого мы не знаем, обязательно: SeverityRank незнакомое молча приравнивает
// к medium, и вызывающий код не может увидеть, что серьёзность на самом деле не
// сообщили. Песочнице это важно — она серьёзность присылает не всегда.
func KnownSeverity(severity string) bool {
	for _, s := range SeverityOrder {
		if s == severity {
			return true
		}
	}
	return false
}

// Finding — находка сканера содержимого.
type Finding struct {
	Scanner  string `json:"scanner"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Matched  string `json:"matched"`
}

// Outcome — результат прогона сканера.
//
// Available=false означает «проверка не выполнена», а не «чисто»: шаг обязан
// превратить это в pending и позвать DevSecOps. Detail в этом случае —
// человекочитаемая причина, она попадает в карточку заявки и в отчёт.
type Outcome struct {
	Available bool
	Detail    string
	Findings  []Finding
}

// WorstSeverity — самая высокая серьёзность среди находок; пусто, если находок
// нет.
func (o Outcome) WorstSeverity() string {
	worst := ""
	rank := -1
	for _, f := range o.Findings {
		if r := SeverityRank(f.Severity); r > rank {
			rank, worst = r, f.Severity
		}
	}
	return worst
}

// AboveThreshold — находки не ниже порога severity. Порог "info" пропускает всё.
func (o Outcome) AboveThreshold(threshold string) []Finding {
	min := SeverityRank(threshold)
	var out []Finding
	for _, f := range o.Findings {
		if SeverityRank(f.Severity) >= min {
			out = append(out, f)
		}
	}
	return out
}

// Scanner — общий контракт обоих сканеров содержимого.
type Scanner interface {
	// Name — имя сканера, оно же пишется в code_finding.scanner и в отчёт.
	Name() string
	// Scan проходит по разложенному каталогу. Ошибку возвращает только на
	// том, что вызывающая сторона обязана заметить как сбой процесса;
	// «сканер недоступен» — это Outcome{Available:false}, не ошибка.
	Scan(ctx context.Context, root string) (Outcome, error)
}

// sortFindings приводит находки к устойчивому порядку: сначала самые
// серьёзные, дальше по файлу и строке. Без этого отчёт двух одинаковых
// прогонов отличался бы порядком строк — и golden-тесты, и глаз ревьюера это
// одинаково не любят.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := SeverityRank(findings[i].Severity), SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

// relativeTo приводит абсолютный путь файла к пути внутри каталога
// распаковки: в отчёт и в БД должен попадать путь внутри пакета, а не
// временный каталог, которого через секунду не будет.
func relativeTo(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// truncate обрезает строку по рунам, а не по байтам: обрезка кириллицы по
// байту даёт битый UTF-8 в JSON-отчёте.
func truncate(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit])
}

// lineIndex — отображение «смещение в байтах -> номер строки» для одного файла.
// YARA отдаёт смещения, а в отчёте нужен номер строки; чтение файла кешируется,
// потому что на один файл приходится обычно несколько совпадений.
type lineIndex struct {
	files map[string][]byte
}

func newLineIndex() *lineIndex {
	return &lineIndex{files: make(map[string][]byte)}
}

func (l *lineIndex) data(path string) []byte {
	if data, ok := l.files[path]; ok {
		return data
	}
	data, err := os.ReadFile(path)
	if err != nil {
		data = nil
	}
	l.files[path] = data
	return data
}

// lineAt — номер строки (с 1) для байтового смещения, как в Python-версии:
// data.count(b"\n", 0, offset) + 1.
func (l *lineIndex) lineAt(path string, offset int) int {
	data := l.data(path)
	if data == nil || offset <= 0 || offset > len(data) {
		return 1
	}
	return strings.Count(string(data[:offset]), "\n") + 1
}

// snippet — фрагмент содержимого по смещению и длине, для колонки «совпало».
func (l *lineIndex) snippet(path string, offset, length int) string {
	data := l.data(path)
	if data == nil || offset < 0 || offset >= len(data) {
		return ""
	}
	end := offset + length
	if length <= 0 || end > len(data) {
		end = len(data)
	}
	return truncate(strings.ToValidUTF8(string(data[offset:end]), "�"), 200)
}

// unavailable — короткий конструктор для «проверка не выполнена».
func unavailable(format string, args ...any) Outcome {
	return Outcome{Available: false, Detail: fmt.Sprintf(format, args...)}
}

// walkFiles обходит обычные файлы каталога, пропуская ссылки и недоступное.
// Общий для сканеров помощник: обоим нужно посчитать, что вообще попало под
// проверку, чтобы Detail не врал.
func walkFiles(root string, fn func(path string, size int64)) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil //nolint:nilerr // недоступный элемент пропускается, а не роняет обход
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		fn(path, info.Size())
		return nil
	})
}

// notFound — бинарь недоступен. exec.Error приходит только когда бинарь искали
// в PATH; при абсолютном пути Start отдаёт голый *fs.PathError, поэтому одной
// проверки exec.ErrNotFound мало — она молча превращала «сканера нет» в
// «сканер упал», и причина недоступности в карточке заявки читалась неверно.
func notFound(err error) bool {
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return true
	}
	return errors.Is(err, exec.ErrNotFound) ||
		errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, fs.ErrPermission)
}

// waitDelay — сколько ждать закрытия каналов вывода после того, как процесс
// убит по таймауту. Без этого прогон зависает на всё время жизни ПОТОМКА
// сканера: убитый процесс закрывает свой конец трубы, а унаследовавший её
// потомок — нет, и Run ждёт его молча, уже за пределами собственного таймаута.
const waitDelay = 15 * time.Second

// proxyVars — переменные, которыми настраивается исходящий прокси.
var proxyVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// scannerEnv — окружение для внешнего сканера: окружение сервиса минус
// ПУСТЫЕ переменные прокси, плюс extra.
//
// Зачем вычищать пустые. docker-compose прокидывает прокси как
// `HTTP_PROXY: ${HTTP_PROXY:-}`, то есть в контейнере переменная ЕСТЬ, но
// пустая, когда прокси не настроен. Почти все инструменты читают это как
// «прокси нет», а semgrep-core (он на OCaml) — падает:
//
//	[WARNING]: HTTPS_PROXY was supplied a URI with no scheme; augmenting it as https://
//	Fatal error: exception Invalid_argument: No host was provided in URI
//
// Снаружи это выглядело как «SAST не работает», причём непонятно почему:
// бинарь на месте, правила заданы, а отчёта нет. Пустая переменная и
// отсутствующая означают одно и то же, поэтому пустую просто не передаём.
//
// Непустые переменные передаются как есть: за правилами `p/default` semgrep
// ходит в реестр, и в закрытой сети без прокси он не работает.
func scannerEnv(extra ...string) []string {
	empty := map[string]bool{}
	for _, name := range proxyVars {
		if value, ok := os.LookupEnv(name); ok && strings.TrimSpace(value) == "" {
			empty[name] = true
		}
	}

	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if empty[name] {
			continue
		}
		env = append(env, entry)
	}
	return append(env, extra...)
}
