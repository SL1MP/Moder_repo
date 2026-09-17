package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// semgrepSeverity — отображение уровней semgrep на наши. 1:1 с Python
// _SEMGREP_SEVERITY; незнакомый уровень даёт "medium" (см. SeverityRank).
var semgrepSeverity = map[string]string{
	"ERROR":   "high",
	"WARNING": "medium",
	"INFO":    "low",
	// semgrep >= 1.x в некоторых правилах отдаёт расширенный набор.
	"CRITICAL": "critical",
	"HIGH":     "high",
	"MEDIUM":   "medium",
	"LOW":      "low",
}

// SemgrepScanner — SAST по исходникам пакета. Бинарь внешний — как и yara,
// как и osv-scanner.
//
// Rules — значение SAST_RULES: либо публичный набор (`p/default`), либо путь к
// приватному файлу правил (в CI используется semgrep_rule_prod.yml — см.
// docs/ci-parity-gaps.md).
type SemgrepScanner struct {
	Binary  string        // по умолчанию "semgrep"
	Rules   string        // --config
	Timeout time.Duration // и на сам semgrep (--timeout), и на процесс
}

func (s SemgrepScanner) Name() string { return "semgrep" }

func (s SemgrepScanner) binary() string {
	if strings.TrimSpace(s.Binary) == "" {
		return "semgrep"
	}
	return s.Binary
}

func (s SemgrepScanner) timeout() time.Duration {
	if s.Timeout <= 0 {
		return 10 * time.Minute
	}
	return s.Timeout
}

func (s SemgrepScanner) Scan(ctx context.Context, root string) (Outcome, error) {
	if strings.TrimSpace(s.Rules) == "" {
		return unavailable("набор правил не задан (SAST_RULES)"), nil
	}

	inner := s.timeout()
	// Процессу даём запас поверх собственного таймаута semgrep: иначе мы
	// убьём его ровно в тот момент, когда он сам собирался аккуратно
	// завершиться и отдать частичный отчёт. Тот же запас (+60с) в Python-версии.
	runCtx, cancel := context.WithTimeout(ctx, inner+60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, s.binary(),
		"--json",
		"--quiet",
		"--no-git-ignore",
		"--timeout", strconv.Itoa(int(inner.Seconds())),
		"--config", s.Rules,
		root,
	)
	// Окружение задаём явно: пустые переменные прокси semgrep-core роняют
	// (см. scannerEnv), а телеметрия и проверка версии — это сетевые вызовы,
	// которых инструменту цепочки поставок здесь делать незачем. Настройки
	// переменными, а не флагами: незнакомый флаг старый semgrep отвергнет
	// целиком, а незнакомую переменную просто не заметит.
	cmd.Env = scannerEnv(
		"SEMGREP_SEND_METRICS=off",
		"SEMGREP_ENABLE_VERSION_CHECK=0",
	)

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
			return unavailable("сканер не уложился в %s", inner), nil
		}
		// Ненулевой код semgrep при непустом JSON — это «есть находки» или
		// «часть файлов не разобрана»: отчёт всё равно валиден, и терять его
		// нельзя. Пустой stdout — настоящая неудача.
		if strings.TrimSpace(stdout.String()) == "" {
			detail := strings.TrimSpace(stderr.String())
			if detail == "" {
				detail = err.Error()
			}
			return unavailable("сканер не вернул отчёт: %s", truncate(detail, 300)), nil
		}
	}

	if strings.TrimSpace(stdout.String()) == "" {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = "пустой ответ сканера"
		}
		return unavailable("сканер не вернул отчёт: %s", truncate(detail, 300)), nil
	}

	var report semgrepReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return unavailable("отчёт сканера не разобран: %v", err), nil
	}

	findings := report.toFindings(root)
	sortFindings(findings)

	detail := "файлов просканировано: " + formatCount(len(report.Paths.Scanned))
	if n := len(report.Errors); n > 0 {
		// Ошибки разбора отдельных файлов — не повод считать прогон
		// несостоявшимся, но и умалчивать о них нельзя: они попадут в отчёт.
		detail += ", файлов с ошибками разбора: " + strconv.Itoa(n)
	}

	return Outcome{Available: true, Detail: detail, Findings: findings}, nil
}

// semgrepReport — та часть JSON-отчёта semgrep, которая нам нужна.
type semgrepReport struct {
	Results []semgrepResult `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
		Path    string `json:"path"`
	} `json:"errors"`
	Paths struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
	} `json:"extra"`
}

func (r semgrepReport) toFindings(root string) []Finding {
	out := make([]Finding, 0, len(r.Results))
	for _, entry := range r.Results {
		severity, ok := semgrepSeverity[strings.ToUpper(strings.TrimSpace(entry.Extra.Severity))]
		if !ok {
			severity = "medium"
		}
		message := truncate(strings.TrimSpace(entry.Extra.Message), 500)
		if message == "" {
			message = "Срабатывание правила SAST"
		}
		ruleID := entry.CheckID
		if strings.TrimSpace(ruleID) == "" {
			ruleID = "semgrep"
		}
		line := entry.Start.Line
		if line < 1 {
			line = 1
		}
		out = append(out, Finding{
			Scanner:  "semgrep",
			RuleID:   ruleID,
			Severity: severity,
			Message:  message,
			File:     relativeTo(root, entry.Path),
			Line:     line,
			Matched:  truncate(strings.TrimSpace(entry.Extra.Lines), 200),
		})
	}
	return out
}
