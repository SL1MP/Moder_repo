package scanners

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// MaxScanFileBytes — файлы крупнее не сканируем содержимым: YARA на них уходит
// в таймаут, а полезного в минифицированных бандлах и бинарях всё равно мало.
// Значение 1:1 с Python-версией.
const MaxScanFileBytes = 16 * 1024 * 1024

// YaraScanner — протестварь и политические баннеры по правилам YARA.
//
// Правила лежат в RulesFile — это тот же файл, что используется в
// CI-конвейерах модерации, чтобы вердикт не расходился между сервисом и CI.
//
// Все находки получают severity "high": баннер — находка сама по себе, порога
// у этого шага нет (см. BannerScanStep, _min_severity == "info" в
// Python-версии — любое совпадение уходит DevSecOps).
type YaraScanner struct {
	Binary    string        // по умолчанию "yara"
	RulesFile string        // BANNER_RULES_FILE
	Timeout   time.Duration // на весь прогон
}

func (s YaraScanner) Name() string { return "yara" }

func (s YaraScanner) binary() string {
	if strings.TrimSpace(s.Binary) == "" {
		return "yara"
	}
	return s.Binary
}

func (s YaraScanner) timeout() time.Duration {
	if s.Timeout <= 0 {
		return 5 * time.Minute
	}
	return s.Timeout
}

func (s YaraScanner) Scan(ctx context.Context, root string) (Outcome, error) {
	if strings.TrimSpace(s.RulesFile) == "" {
		return unavailable("файл правил не задан (BANNER_RULES_FILE)"), nil
	}
	if _, err := os.Stat(s.RulesFile); err != nil {
		return unavailable("файл правил не найден: %s", s.RulesFile), nil
	}

	runCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()

	// Флаги: печатать совпавшие строки и их длину, рекурсивно по каталогу,
	// без предупреждений (иначе предупреждения компиляции правил
	// перемешиваются с результатами в stdout), не следовать по символическим
	// ссылкам (распаковщик их и так не создаёт, но каталог сканирования может
	// прийти и не от него).
	//
	// Ограничение --max-strings-per-rule здесь БЫЛО и убрано: боевой набор
	// правил (config/rules.yar) его не проходит — правило
	// protestware__EventSource содержит больше 32 строк, и yara отказывалась
	// компилировать весь файл целиком. Поймано только живым прогоном:
	// юнит-тесты идут на фейковом бинаре, который аргументы игнорирует.
	cmd := exec.CommandContext(runCtx, s.binary(),
		"--print-strings",
		"--print-string-length",
		"--recursive",
		"--no-warnings",
		"--no-follow-symlinks",
		s.RulesFile,
		root,
	)
	// Тот же приём, что у semgrep: пустые переменные прокси во внешний
	// процесс не передаём. yara в сеть не ходит, но единообразный запуск
	// дешевле, чем два разных способа собрать окружение.
	cmd.Env = scannerEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	if err != nil {
		if notFound(err) {
			return unavailable("сканер не установлен: %s", s.binary()), nil
		}
		if runCtx.Err() != nil {
			return unavailable("сканер не уложился в %s", s.timeout()), nil
		}
		// yara отдаёт ненулевой код на ошибках компиляции правил и доступа к
		// файлам. Совпадения таким кодом не сопровождаются, поэтому любой
		// ненулевой код — это «проверка не выполнена», а не «найдено».
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return unavailable("сканер завершился с ошибкой: %s", truncate(detail, 300)), nil
	}

	findings := parseYaraOutput(stdout.String(), root)
	sortFindings(findings)

	scanned, err := countScannableFiles(root)
	if err != nil {
		scanned = -1
	}
	triggered := map[string]struct{}{}
	for _, f := range findings {
		triggered[f.RuleID] = struct{}{}
	}
	detail := "просканировано файлов: " + formatCount(scanned) +
		", правил сработало: " + strconv.Itoa(len(triggered))

	return Outcome{Available: true, Detail: detail, Findings: findings}, nil
}

func formatCount(n int) string {
	if n < 0 {
		return "—"
	}
	return strconv.Itoa(n)
}

// countScannableFiles — сколько файлов реально попало бы под сканирование;
// нужно только для Detail (сам обход делает yara). Крупные файлы исключаются
// по тому же правилу MaxScanFileBytes, что и в Python-версии.
func countScannableFiles(root string) (int, error) {
	count := 0
	err := walkFiles(root, func(path string, size int64) {
		if size <= MaxScanFileBytes {
			count++
		}
	})
	return count, err
}

// parseYaraOutput разбирает вывод `yara -s -r`.
//
// Формат:
//
//	<имя правила> <путь к файлу>
//	0x1f:12:$identifier: совпавший текст
//
// Строка совпадения относится к последней объявленной паре (правило, файл).
// Имя правила пробелов не содержит, а путь — может, поэтому делим по первому
// пробелу. Правило без строк (например, по хешу файла) даёт только первую
// строку — находка всё равно есть (то же поведение, что в Python `_yara_findings`).
func parseYaraOutput(stdout, root string) []Finding {
	lines := newLineIndex()
	var findings []Finding

	var currentRule, currentPath string
	// seen — чтобы не плодить по находке на каждое совпадение в одной строке
	// одного правила (Python делает то же через set (rule, line)).
	seen := map[string]struct{}{}
	matchedForCurrent := false

	flushRuleWithoutStrings := func() {
		if currentRule == "" || matchedForCurrent {
			return
		}
		findings = append(findings, Finding{
			Scanner:  "yara",
			RuleID:   currentRule,
			Severity: "high",
			Message:  "Совпадение правила «" + currentRule + "» по содержимому файла",
			File:     relativeTo(root, currentPath),
			Line:     1,
		})
	}

	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		if !strings.HasPrefix(line, "0x") {
			// Новая пара «правило — файл».
			flushRuleWithoutStrings()
			rule, path, ok := strings.Cut(line, " ")
			if !ok {
				continue
			}
			// Правило может быть напечатано с пространством имён (ns:rule) —
			// в находку кладём полное имя, оно же в правилах CI.
			currentRule, currentPath = strings.TrimSpace(rule), strings.TrimSpace(path)
			matchedForCurrent = false
			continue
		}

		if currentRule == "" {
			continue
		}
		offset, length, identifier, ok := parseYaraMatchLine(line)
		if !ok {
			continue
		}
		lineNo := lines.lineAt(currentPath, offset)
		key := currentRule + "\x00" + currentPath + "\x00" + strconv.Itoa(lineNo)
		if _, dup := seen[key]; dup {
			matchedForCurrent = true
			continue
		}
		seen[key] = struct{}{}
		matchedForCurrent = true

		findings = append(findings, Finding{
			Scanner:  "yara",
			RuleID:   currentRule,
			Severity: "high",
			Message:  "Совпадение правила «" + currentRule + "» (" + identifier + ")",
			File:     relativeTo(root, currentPath),
			Line:     lineNo,
			Matched:  lines.snippet(currentPath, offset, length),
		})
	}
	flushRuleWithoutStrings()
	return findings
}

// parseYaraMatchLine разбирает строку совпадения.
//
// С --print-string-length формат: `0x<offset>:<length>:$<id>: <данные>`.
// Без него (старые сборки yara) — `0x<offset>:$<id>: <данные>`; поддерживаем
// оба, чтобы версия бинаря в образе не ломала разбор молча.
func parseYaraMatchLine(line string) (offset, length int, identifier string, ok bool) {
	rest := strings.TrimPrefix(line, "0x")
	offsetHex, rest, found := strings.Cut(rest, ":")
	if !found {
		return 0, 0, "", false
	}
	parsed, err := strconv.ParseInt(offsetHex, 16, 64)
	if err != nil {
		return 0, 0, "", false
	}
	offset = int(parsed)

	next, tail, found := strings.Cut(rest, ":")
	if !found {
		return 0, 0, "", false
	}
	if !strings.HasPrefix(next, "$") {
		// Это длина совпадения, идентификатор — следующим полем.
		if n, err := strconv.Atoi(next); err == nil {
			length = n
		}
		next, tail, found = strings.Cut(tail, ":")
		if !found {
			return 0, 0, "", false
		}
	}
	_ = tail
	return offset, length, strings.TrimSpace(next), true
}
