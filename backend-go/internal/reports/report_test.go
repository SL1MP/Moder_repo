package reports_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"moderation/internal/reports"
	"moderation/internal/scanners"
)

func fixedNow() time.Time {
	return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
}

func sampleInput() reports.Input {
	return reports.Input{
		Package: reports.Package{
			Manager: "pypi", Name: "six", Version: "1.16.0",
			DisplayName: "six", Artifact: "six-1.16.0-py2.py3-none-any.whl",
			SHA256: "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254",
		},
		Kind:      reports.KindSAST,
		Scanner:   "semgrep",
		Rules:     "p/default",
		Threshold: "medium",
		Outcome: scanners.Outcome{
			Available: true,
			Detail:    "файлов просканировано: 12",
			Findings: []scanners.Finding{
				{Scanner: "semgrep", RuleID: "python.dangerous-exec", Severity: "high",
					Message: "Вызов exec с внешними данными", File: "six.py", Line: 42,
					Matched: "exec(code)"},
				{Scanner: "semgrep", RuleID: "python.no-print", Severity: "low",
					Message: "print в библиотеке", File: "six.py", Line: 7, Matched: "print(x)"},
			},
		},
		Unpacked:  reports.Unpacked{Files: 12, TotalBytes: 40960},
		RequestID: 7, ItemID: 11,
		StartedAt: fixedNow(),
		EndedAt:   fixedNow().Add(2500 * time.Millisecond),
		Now:       fixedNow,
	}
}

func TestBuildSummary(t *testing.T) {
	r := reports.Build(sampleInput())

	if r.Schema != reports.SchemaVersion {
		t.Errorf("Schema = %q", r.Schema)
	}
	if r.Summary.Total != 2 {
		t.Errorf("Total = %d, ожидалось 2", r.Summary.Total)
	}
	// Порог medium: low не блокирует.
	if r.Summary.Blocking != 1 {
		t.Errorf("Blocking = %d, ожидался 1 (порог medium отсекает low)", r.Summary.Blocking)
	}
	if r.Summary.WorstSeverity != "high" {
		t.Errorf("WorstSeverity = %q", r.Summary.WorstSeverity)
	}
	if r.Summary.FilesAffected != 1 {
		t.Errorf("FilesAffected = %d, обе находки в одном файле", r.Summary.FilesAffected)
	}
	if len(r.Summary.RulesTriggered) != 2 {
		t.Errorf("RulesTriggered = %v", r.Summary.RulesTriggered)
	}
	if r.Scan.DurationMs != 2500 {
		t.Errorf("DurationMs = %d, ожидалось 2500", r.Scan.DurationMs)
	}
	if r.State() != "findings" {
		t.Errorf("State = %q", r.State())
	}
}

// TestUnavailableScanIsNotClean — самое важное свойство отчёта: прогон, который
// не состоялся, обязан читаться как «не проверено», а не как «чисто».
func TestUnavailableScanIsNotClean(t *testing.T) {
	in := sampleInput()
	in.Outcome = scanners.Outcome{Available: false, Detail: "сканер не установлен: semgrep"}
	r := reports.Build(in)

	if r.State() != "unavailable" {
		t.Errorf("State = %q, ожидалось unavailable", r.State())
	}
	if r.Scan.Completed {
		t.Error("Completed=true у несостоявшегося прогона")
	}
	if !strings.Contains(r.Verdict(), "не выполнена") {
		t.Errorf("Verdict = %q", r.Verdict())
	}

	html, err := r.HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(html)
	if !strings.Contains(body, "не потому, что пакет чист") {
		t.Error("HTML не объясняет, что пустой список находок здесь не означает чистоту")
	}
	if !strings.Contains(body, "сканер не установлен") {
		t.Error("причина недоступности потеряна в HTML")
	}
}

func TestCleanScan(t *testing.T) {
	in := sampleInput()
	in.Outcome = scanners.Outcome{Available: true, Detail: "просканировано файлов: 12, правил сработало: 0"}
	r := reports.Build(in)

	if r.State() != "clean" {
		t.Errorf("State = %q", r.State())
	}
	if r.Verdict() != "Срабатываний нет" {
		t.Errorf("Verdict = %q", r.Verdict())
	}
}

func TestBelowThresholdIsStillClean(t *testing.T) {
	in := sampleInput()
	in.Outcome.Findings = []scanners.Finding{
		{RuleID: "r", Severity: "low", Message: "m", File: "a.py", Line: 1},
	}
	r := reports.Build(in)

	if r.State() != "clean" {
		t.Errorf("State = %q, находка ниже порога не должна блокировать", r.State())
	}
	if !strings.Contains(r.Verdict(), "ниже порога: 1") {
		t.Errorf("Verdict = %q, находки ниже порога должны быть упомянуты", r.Verdict())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	r := reports.Build(sampleInput())
	data, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var back reports.Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("отчёт не разбирается обратно: %v", err)
	}
	if back.Summary.Blocking != r.Summary.Blocking || len(back.Findings) != len(r.Findings) {
		t.Error("отчёт не совпал после round-trip")
	}
	if back.Package.SHA256 != r.Package.SHA256 {
		t.Error("sha256 потерян")
	}
}

// TestJSONKeepsCyrillicAndAngleBrackets — та же мина, что с логами Python-версии
// (handoff, п. 8.4): экранированный отчёт нечитаем и не грепается.
func TestJSONKeepsCyrillicAndAngleBrackets(t *testing.T) {
	in := sampleInput()
	in.Outcome.Findings = []scanners.Finding{{
		RuleID: "js.xss", Severity: "high",
		Message: "Небезопасная вставка в DOM",
		File:    "index.js", Line: 3,
		Matched: `el.innerHTML = "<script>" + a & b`,
	}}
	data, err := reports.Build(in).JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "Небезопасная вставка в DOM") {
		t.Error("кириллица экранирована — отчёт нечитаем и не грепается")
	}
	if !strings.Contains(body, "<script>") {
		t.Error("угловые скобки экранированы (\\u003c) — фрагмент кода нечитаем")
	}
	if !strings.Contains(body, "a & b") {
		t.Error("амперсанд экранирован")
	}
}

// TestHTMLEscapesUntrustedContent — в отчёт попадает содержимое проверяемого
// пакета. Отчёт о подозрительном пакете открывает ровно тот человек, который
// его расследует: скрипт из пакета не должен там выполниться.
func TestHTMLEscapesUntrustedContent(t *testing.T) {
	in := sampleInput()
	in.Package.Name = `six<script>alert(1)</script>`
	in.Outcome.Findings = []scanners.Finding{{
		RuleID:   `<img src=x onerror=alert(2)>`,
		Severity: "high",
		Message:  `<b>жирный</b> и <script>alert(3)</script>`,
		File:     `<svg onload=alert(4)>.py`,
		Line:     1,
		Matched:  `</pre><script>alert(5)</script>`,
	}}
	html, err := reports.Build(in).HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(html)

	for _, payload := range []string{
		"<script>alert(1)", "<img src=x onerror", "<script>alert(3)",
		"<svg onload=", "<script>alert(5)",
	} {
		if strings.Contains(body, payload) {
			t.Errorf("недоверенное содержимое попало в HTML без экранирования: %q", payload)
		}
	}
	// Экранированный вид при этом присутствовать обязан — иначе мы просто
	// потеряли находку.
	if !strings.Contains(body, "&lt;script&gt;alert(1)") {
		t.Error("экранированное содержимое отсутствует — находка потеряна, а не обезврежена")
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	html, err := reports.Build(sampleInput()).HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(html)
	for _, external := range []string{"http://", "https://", "<script", "@import"} {
		if strings.Contains(body, external) {
			t.Errorf("отчёт не самодостаточен: найдено %q", external)
		}
	}
	if !strings.HasPrefix(body, "<!doctype html>") {
		t.Error("нет doctype")
	}
}

func TestHTMLShowsFindingsAndTruncation(t *testing.T) {
	in := sampleInput()
	in.Unpacked = reports.Unpacked{
		Files: 20000, Truncated: true, SkippedUnsafe: 2, SkippedLarge: 1,
		Notes: []string{"распаковка ограничена: 20000 файлов, 512 МБ — часть содержимого не проверена"},
	}
	html, err := reports.Build(in).HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(html)

	if !strings.Contains(body, "python.dangerous-exec") {
		t.Error("правило находки отсутствует в HTML")
	}
	if !strings.Contains(body, "строка 42") {
		t.Error("номер строки отсутствует в HTML")
	}
	if !strings.Contains(body, "часть содержимого не проверена") {
		t.Error("ограничение распаковки не показано — «находок нет» читалось бы как «пакет чист»")
	}
	if !strings.Contains(body, "Пропущено небезопасных путей") {
		t.Error("небезопасные пути в архиве не показаны")
	}
	if !strings.Contains(body, "блокирует") {
		t.Error("не отмечено, какие находки блокируют публикацию")
	}
}

func TestHTMLShowsDecision(t *testing.T) {
	in := sampleInput()
	in.Decision = &reports.Decision{
		Kind: "security_override", DecidedBy: "Пётр Петров",
		DecidedAt: fixedNow(), Comment: "Ложное срабатывание, проверено вручную",
	}
	html, err := reports.Build(in).HTML()
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(html)
	if !strings.Contains(body, "Пётр Петров") || !strings.Contains(body, "Ложное срабатывание") {
		t.Error("решение DevSecOps не показано — находки выглядели бы необъяснённо проигнорированными")
	}
}

func TestBannerKindTitleAndFileName(t *testing.T) {
	in := sampleInput()
	in.Kind = reports.KindBanner
	in.Scanner = "yara"
	in.Threshold = "" // у баннеров порога нет
	r := reports.Build(in)

	if r.Scan.Title != "Политические баннеры" {
		t.Errorf("Title = %q", r.Scan.Title)
	}
	if r.Scan.Threshold != "info" {
		t.Errorf("пустой порог должен становиться info, а не %q", r.Scan.Threshold)
	}
	// Порог info -> блокирует всё.
	if r.Summary.Blocking != 2 {
		t.Errorf("Blocking = %d, у баннеров блокирует любое совпадение", r.Summary.Blocking)
	}
	if got := r.FileName("json"); got != "banner_scan-six-1.16.0.json" {
		t.Errorf("FileName = %q", got)
	}
}

func TestFileNameSanitizesPathSeparators(t *testing.T) {
	in := sampleInput()
	in.Package.Name = "@scope/pkg"
	in.Package.Version = "1.0.0+build/1"
	r := reports.Build(in)
	name := r.FileName("html")
	if strings.ContainsAny(name, "/\\@+") {
		t.Errorf("FileName = %q содержит символы, опасные для пути объекта", name)
	}
}
