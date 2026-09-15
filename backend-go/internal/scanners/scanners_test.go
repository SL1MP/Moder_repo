package scanners

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeBinary кладёт исполняемый sh-скрипт, печатающий заданный stdout и
// завершающийся заданным кодом. Так разбор вывода проверяется без установки
// настоящих yara/semgrep — их наличие в CI не гарантировано, а логика разбора
// ломается тихо и стоит дорого.
func fakeBinary(t *testing.T, stdout, stderr string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("фейковый бинарь собирается через sh — тест для unix-окружения")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-scanner")
	script := "#!/bin/sh\n" +
		"cat <<'__STDOUT__'\n" + stdout + "\n__STDOUT__\n" +
		"cat >&2 <<'__STDERR__'\n" + stderr + "\n__STDERR__\n" +
		"exit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("запись фейкового бинаря: %v", err)
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// scanTree раскладывает файлы и возвращает корень — то, что сканеру подаётся
// на вход после распаковки артефакта.
func scanTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("каталог для %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("запись %s: %v", name, err)
		}
	}
	return root
}

// --------------------------------------------------------------------- severity

func TestSeverityRank(t *testing.T) {
	if SeverityRank("critical") <= SeverityRank("high") {
		t.Error("critical должен быть выше high")
	}
	if SeverityRank("info") != 0 {
		t.Errorf("info = %d, ожидалось 0", SeverityRank("info"))
	}
	// Незнакомый уровень приравнивается к medium, а не к info: незнакомое не
	// должно тихо проваливаться ниже порога.
	if SeverityRank("совершенно новый") != SeverityRank("medium") {
		t.Error("незнакомый уровень должен приравниваться к medium")
	}
}

func TestAboveThreshold(t *testing.T) {
	out := Outcome{Findings: []Finding{
		{Severity: "low"}, {Severity: "high"}, {Severity: "medium"}, {Severity: "critical"},
	}}
	if got := len(out.AboveThreshold("info")); got != 4 {
		t.Errorf("порог info пропустил %d находок, ожидалось 4", got)
	}
	if got := len(out.AboveThreshold("high")); got != 2 {
		t.Errorf("порог high дал %d находок, ожидалось 2", got)
	}
	if got := out.WorstSeverity(); got != "critical" {
		t.Errorf("WorstSeverity = %q, ожидалось critical", got)
	}
}

func TestWorstSeverityEmpty(t *testing.T) {
	if got := (Outcome{}).WorstSeverity(); got != "" {
		t.Errorf("WorstSeverity без находок = %q, ожидалась пустая строка", got)
	}
}

// --------------------------------------------------------------------- YARA

// TestYaraMissingRulesIsUnavailable — центральное правило обоих сканеров:
// недоступный сканер НЕ значит «чисто».
func TestYaraMissingRulesIsUnavailable(t *testing.T) {
	s := YaraScanner{RulesFile: filepath.Join(t.TempDir(), "нет-такого.yar")}
	out, err := s.Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan вернул ошибку вместо Available=false: %v", err)
	}
	if out.Available {
		t.Fatal("отсутствующий файл правил дал Available=true — пакет проскочил бы проверку")
	}
	if !strings.Contains(out.Detail, "не найден") {
		t.Errorf("Detail = %q, причина недоступности не названа", out.Detail)
	}
}

func TestYaraMissingBinaryIsUnavailable(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(rules, []byte("rule x { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := YaraScanner{Binary: "/nonexistent/yara-binary", RulesFile: rules}
	out, err := s.Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Available {
		t.Fatal("отсутствующий бинарь дал Available=true")
	}
	if !strings.Contains(out.Detail, "не установлен") {
		t.Errorf("Detail = %q", out.Detail)
	}
}

func TestYaraParsesMatches(t *testing.T) {
	root := scanTree(t, map[string]string{
		"pkg/banner.js": "line one\nconst msg = 'Слава Україні';\nline three\n",
	})
	target := filepath.Join(root, "pkg", "banner.js")
	// Смещение фразы в файле — считаем честно, чтобы проверить пересчёт в
	// номер строки, а не подогнать константу.
	data, _ := os.ReadFile(target)
	offset := strings.Index(string(data), "Слава")

	stdout := "political_banner " + target + "\n" +
		"0x" + hex(offset) + ":10:$slogan: Слава\n"
	rules := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(rules, []byte("rule political_banner { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := YaraScanner{Binary: fakeBinary(t, stdout, "", 0), RulesFile: rules}
	out, err := s.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !out.Available {
		t.Fatalf("Available=false: %s", out.Detail)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %+v", len(out.Findings), out.Findings)
	}
	f := out.Findings[0]
	if f.RuleID != "political_banner" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, у баннеров всегда high", f.Severity)
	}
	if f.Line != 2 {
		t.Errorf("Line = %d, фраза на второй строке", f.Line)
	}
	if f.File != "pkg/banner.js" {
		t.Errorf("File = %q, ожидался путь внутри пакета", f.File)
	}
	if !strings.Contains(f.Matched, "Слава") {
		t.Errorf("Matched = %q, фрагмент содержимого не подставлен", f.Matched)
	}
}

// TestYaraRuleWithoutStrings — правило по хешу файла даёт только строку
// «правило файл», без совпадений. Находка всё равно должна появиться.
func TestYaraRuleWithoutStrings(t *testing.T) {
	root := scanTree(t, map[string]string{"a.bin": "содержимое"})
	rules := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(rules, []byte("rule by_hash { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout := "by_hash " + filepath.Join(root, "a.bin")

	s := YaraScanner{Binary: fakeBinary(t, stdout, "", 0), RulesFile: rules}
	out, err := s.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1", len(out.Findings))
	}
	if out.Findings[0].RuleID != "by_hash" {
		t.Errorf("RuleID = %q", out.Findings[0].RuleID)
	}
}

func TestYaraNonZeroExitIsUnavailable(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(rules, []byte("rule x { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := YaraScanner{Binary: fakeBinary(t, "", "error: rules not compiled", 1), RulesFile: rules}
	out, err := s.Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Available {
		t.Fatal("ошибка компиляции правил дала Available=true")
	}
	if !strings.Contains(out.Detail, "rules not compiled") {
		t.Errorf("Detail = %q, stderr сканера потерян", out.Detail)
	}
}

func hex(n int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%16]}, b...)
		n /= 16
	}
	return string(b)
}

func TestParseYaraMatchLineBothFormats(t *testing.T) {
	// С --print-string-length.
	offset, length, id, ok := parseYaraMatchLine("0x1f:12:$slogan: текст")
	if !ok || offset != 0x1f || length != 12 || id != "$slogan" {
		t.Errorf("новый формат разобран как offset=%d length=%d id=%q ok=%v", offset, length, id, ok)
	}
	// Без неё (старые сборки yara).
	offset, length, id, ok = parseYaraMatchLine("0x2a:$s1: текст")
	if !ok || offset != 0x2a || length != 0 || id != "$s1" {
		t.Errorf("старый формат разобран как offset=%d length=%d id=%q ok=%v", offset, length, id, ok)
	}
	// Мусор не должен паниковать и не должен давать находку.
	if _, _, _, ok := parseYaraMatchLine("0xZZ:мусор"); ok {
		t.Error("мусорная строка разобрана как совпадение")
	}
}

// --------------------------------------------------------------------- semgrep

func TestSemgrepMissingBinaryIsUnavailable(t *testing.T) {
	s := SemgrepScanner{Binary: "/nonexistent/semgrep", Rules: "p/default"}
	out, err := s.Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Available {
		t.Fatal("отсутствующий бинарь дал Available=true")
	}
	if !strings.Contains(out.Detail, "не установлен") {
		t.Errorf("Detail = %q", out.Detail)
	}
}

func TestSemgrepNoRulesIsUnavailable(t *testing.T) {
	out, err := SemgrepScanner{Rules: "  "}.Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Available {
		t.Fatal("пустой SAST_RULES дал Available=true")
	}
}

func TestSemgrepParsesReport(t *testing.T) {
	root := scanTree(t, map[string]string{"pkg/app.py": "import os\nos.system(cmd)\n"})
	report := `{
	  "results": [
	    {
	      "check_id": "python.lang.security.dangerous-system-call",
	      "path": "` + filepath.Join(root, "pkg", "app.py") + `",
	      "start": {"line": 2},
	      "extra": {
	        "message": "Обнаружен вызов os.system с непроверенным аргументом",
	        "severity": "ERROR",
	        "lines": "os.system(cmd)"
	      }
	    },
	    {
	      "check_id": "python.lang.best-practice.no-print",
	      "path": "` + filepath.Join(root, "pkg", "app.py") + `",
	      "start": {"line": 1},
	      "extra": {"message": "print в библиотеке", "severity": "INFO", "lines": "print(1)"}
	    }
	  ],
	  "errors": [],
	  "paths": {"scanned": ["pkg/app.py"]}
	}`

	s := SemgrepScanner{Binary: fakeBinary(t, report, "", 1), Rules: "p/default"}
	out, err := s.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Ненулевой код при непустом JSON — это «есть находки», отчёт валиден.
	if !out.Available {
		t.Fatalf("Available=false при валидном отчёте: %s", out.Detail)
	}
	if len(out.Findings) != 2 {
		t.Fatalf("находок %d, ожидалось 2", len(out.Findings))
	}
	// Сортировка: сначала самые серьёзные.
	if out.Findings[0].Severity != "high" {
		t.Errorf("первая находка severity = %q, ожидалась high", out.Findings[0].Severity)
	}
	if out.Findings[0].File != "pkg/app.py" {
		t.Errorf("File = %q, ожидался путь внутри пакета", out.Findings[0].File)
	}
	if out.Findings[1].Severity != "low" {
		t.Errorf("вторая находка severity = %q, ожидалась low (INFO)", out.Findings[1].Severity)
	}
	if !strings.Contains(out.Findings[0].Message, "os.system") {
		t.Errorf("Message = %q", out.Findings[0].Message)
	}
}

func TestSemgrepBrokenJSONIsUnavailable(t *testing.T) {
	s := SemgrepScanner{Binary: fakeBinary(t, "{это не json", "", 0), Rules: "p/default"}
	out, err := s.Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Available {
		t.Fatal("нечитаемый отчёт дал Available=true")
	}
	if !strings.Contains(out.Detail, "не разобран") {
		t.Errorf("Detail = %q", out.Detail)
	}
}

func TestSemgrepEmptyOutputIsUnavailable(t *testing.T) {
	s := SemgrepScanner{Binary: fakeBinary(t, "", "semgrep: fatal", 2), Rules: "p/default"}
	out, err := s.Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Available {
		t.Fatal("пустой вывод дал Available=true")
	}
	if !strings.Contains(out.Detail, "fatal") {
		t.Errorf("Detail = %q, stderr потерян", out.Detail)
	}
}

func TestSemgrepUnknownSeverityIsMedium(t *testing.T) {
	root := t.TempDir()
	report := `{"results":[{"check_id":"r","path":"a.py","start":{"line":1},
	  "extra":{"message":"m","severity":"НЕЧТО","lines":"x"}}],"paths":{"scanned":["a.py"]}}`
	s := SemgrepScanner{Binary: fakeBinary(t, report, "", 0), Rules: "p/default"}
	out, err := s.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out.Findings) != 1 || out.Findings[0].Severity != "medium" {
		t.Errorf("незнакомый severity не приведён к medium: %+v", out.Findings)
	}
}

func TestSemgrepTimeoutIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "slow")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Внутренний таймаут 1с даёт процессу 61с; ограничиваем внешним контекстом.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	out, err := SemgrepScanner{Binary: path, Rules: "p/default", Timeout: time.Second}.Scan(ctx, dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Available {
		t.Fatal("таймаут дал Available=true")
	}
}
