package reports

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

// HTML рендерит самодостаточную страницу отчёта: без внешних стилей, шрифтов и
// скриптов. Отчёт должен открываться и с диска, и из письма, и на машине, где
// внешние ресурсы режет политика безопасности.
//
// Шаблон html/template, а не ручная склейка строк: в отчёт попадает содержимое
// проверяемого пакета (совпавший фрагмент кода, имена файлов, тексты правил) —
// то есть данные из недоверенного источника. Ручная склейка здесь означала бы
// XSS в отчёте о безопасности, открываемом ровно тем человеком, который
// расследует подозрительный пакет.
func (r *Report) HTML() ([]byte, error) {
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, newView(r)); err != nil {
		return nil, fmt.Errorf("рендер HTML-отчёта: %w", err)
	}
	return buf.Bytes(), nil
}

// view — данные шаблона в уже подготовленном для показа виде: шаблон не должен
// заниматься вычислениями, иначе ошибки в нём не ловятся компилятором.
type view struct {
	*Report
	Verdict        string
	State          string
	StateLabel     string
	PackageRef     string
	GeneratedLocal string
	Severities     []severityRow
	Findings       []findingRow
	Notes          []string
	HasFindings    bool
	Rules          string
}

type severityRow struct {
	Name  string
	Label string
	Count int
}

type findingRow struct {
	scanRowIndex int
	Severity     string
	Label        string
	RuleID       string
	Message      string
	File         string
	Line         int
	Matched      string
	Blocking     bool
}

// severityLabels — подписи уровней по-русски. Отчёт читает не только
// DevSecOps, но и разработчик, которому пакет вернули.
var severityLabels = map[string]string{
	"critical": "Критический",
	"high":     "Высокий",
	"medium":   "Средний",
	"low":      "Низкий",
	"info":     "Информационный",
}

func severityLabel(name string) string {
	if label, ok := severityLabels[name]; ok {
		return label
	}
	return name
}

func newView(r *Report) view {
	v := view{
		Report:         r,
		Verdict:        r.Verdict(),
		State:          r.State(),
		PackageRef:     r.Package.Ref(),
		GeneratedLocal: r.GeneratedAt.Format("2006-01-02 15:04:05 MST"),
		Notes:          r.Unpacked.Notes,
		HasFindings:    len(r.Findings) > 0,
		Rules:          r.Scan.Rules,
	}
	switch r.State() {
	case "unavailable":
		v.StateLabel = "Проверка не выполнена"
	case "findings":
		v.StateLabel = "Есть срабатывания"
	default:
		v.StateLabel = "Чисто"
	}

	// Сводка по уровням — в порядке убывания серьёзности, только непустые.
	for i := len(severityOrderDesc) - 1; i >= 0; i-- {
		name := severityOrderDesc[i]
		if count := r.Summary.BySeverity[name]; count > 0 {
			v.Severities = append(v.Severities, severityRow{
				Name: name, Label: severityLabel(name), Count: count,
			})
		}
	}

	blockingRank := rankOf(r.Scan.Threshold)
	for i, f := range r.Findings {
		v.Findings = append(v.Findings, findingRow{
			scanRowIndex: i,
			Severity:     f.Severity,
			Label:        severityLabel(f.Severity),
			RuleID:       f.RuleID,
			Message:      f.Message,
			File:         f.File,
			Line:         f.Line,
			Matched:      strings.TrimRight(f.Matched, "\n"),
			Blocking:     rankOf(f.Severity) >= blockingRank,
		})
	}
	return v
}

// severityOrderDesc — тот же порядок, что scanners.SeverityOrder; дублируется
// намеренно локально, чтобы шаблон не тянул зависимость на пакет сканеров
// ради подписи.
var severityOrderDesc = []string{"info", "low", "medium", "high", "critical"}

func rankOf(severity string) int {
	for i, s := range severityOrderDesc {
		if s == severity {
			return i
		}
	}
	return 2
}

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Scan.Title}} — {{.PackageRef}}</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #fff; --ink: #1d2433; --muted: #5b6577; --line: #e2e6ed;
    --clean: #107c41; --findings: #b54708; --unavailable: #b42318;
    --critical: #912018; --high: #b54708; --medium: #a15c07; --low: #175cd3; --info: #5b6577;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px 16px; background: var(--bg); color: var(--ink);
    font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }
  .wrap { max-width: 1040px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 24px 0 8px; }
  .sub { color: var(--muted); margin: 0 0 16px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .verdict { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 15px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .state-clean .dot { background: var(--clean); }
  .state-findings .dot { background: var(--findings); }
  .state-unavailable .dot { background: var(--unavailable); }
  .state-clean .state { color: var(--clean); }
  .state-findings .state { color: var(--findings); }
  .state-unavailable .state { color: var(--unavailable); }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }
  dt { color: var(--muted); }
  dd { margin: 0; word-break: break-word; }
  .pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }
  .pill { border: 1px solid var(--line); border-radius: 999px; padding: 2px 10px; font-size: 13px; }
  .pill b { font-weight: 600; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 13px; }
  td.sev { white-space: nowrap; font-weight: 600; }
  .sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
  .sev-medium { color: var(--medium); } .sev-low { color: var(--low); } .sev-info { color: var(--info); }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
  pre { margin: 6px 0 0; padding: 8px; background: #f2f4f7; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
  .loc { color: var(--muted); font-size: 12.5px; }
  .note { border-left: 3px solid var(--findings); padding-left: 10px; color: var(--muted); margin: 6px 0; }
  .blocking { font-size: 12px; color: var(--findings); font-weight: 600; }
  .empty { color: var(--muted); }
  footer { color: var(--muted); font-size: 12.5px; margin-top: 24px; }
  @media (max-width: 640px) { dl { grid-template-columns: 1fr; } dt { margin-top: 6px; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>{{.Scan.Title}}</h1>
  <p class="sub">{{.PackageRef}}</p>

  <div class="card state-{{.State}}">
    <div class="verdict"><span class="dot"></span><span class="state">{{.StateLabel}}</span></div>
    <p style="margin:8px 0 0">{{.Verdict}}</p>
    {{if .Scan.Detail}}<p class="sub" style="margin:6px 0 0">{{.Scan.Detail}}</p>{{end}}
    {{if .Severities}}
    <div class="pills">
      {{range .Severities}}<span class="pill sev-{{.Name}}"><b>{{.Count}}</b> · {{.Label}}</span>{{end}}
    </div>
    {{end}}
  </div>

  {{if .Decision}}
  <div class="card">
    <h2 style="margin-top:0">Решение DevSecOps</h2>
    <dl>
      <dt>Кто</dt><dd>{{.Decision.DecidedBy}}</dd>
      <dt>Когда</dt><dd>{{.Decision.DecidedAt.Format "2006-01-02 15:04:05 MST"}}</dd>
      {{if .Decision.Comment}}<dt>Комментарий</dt><dd>{{.Decision.Comment}}</dd>{{end}}
    </dl>
    <p class="sub" style="margin:8px 0 0">Публикация разрешена вручную — находки ниже приведены для истории.</p>
  </div>
  {{end}}

  <div class="card">
    <h2 style="margin-top:0">Что проверяли</h2>
    <dl>
      <dt>Пакет</dt><dd>{{.Package.Name}}</dd>
      <dt>Версия</dt><dd>{{.Package.Version}}</dd>
      <dt>Менеджер</dt><dd>{{.Package.Manager}}</dd>
      {{if .Package.Artifact}}<dt>Артефакт</dt><dd>{{.Package.Artifact}}</dd>{{end}}
      {{if .Package.SHA256}}<dt>sha256</dt><dd><code>{{.Package.SHA256}}</code></dd>{{end}}
      <dt>Сканер</dt><dd>{{.Scan.Scanner}}</dd>
      {{if .Rules}}<dt>Правила</dt><dd><code>{{.Rules}}</code></dd>{{end}}
      <dt>Порог</dt><dd>{{.Scan.Threshold}}</dd>
      <dt>Файлов разложено</dt><dd>{{.Unpacked.Files}}{{if .Unpacked.Truncated}} (распаковка ограничена){{end}}</dd>
      {{if .Scan.DurationMs}}<dt>Длительность</dt><dd>{{.Scan.DurationMs}} мс</dd>{{end}}
    </dl>
    {{if .Notes}}
      {{range .Notes}}<p class="note">{{.}}</p>{{end}}
    {{end}}
    {{if gt .Unpacked.SkippedUnsafe 0}}
    <p class="note">Пропущено небезопасных путей в архиве: {{.Unpacked.SkippedUnsafe}}
    (выход за пределы каталога или символические ссылки).</p>
    {{end}}
    {{if gt .Unpacked.SkippedLarge 0}}
    <p class="note">Пропущено слишком крупных файлов: {{.Unpacked.SkippedLarge}} — их содержимое не проверено.</p>
    {{end}}
  </div>

  <h2>Находки{{if .HasFindings}} ({{.Summary.Total}}){{end}}</h2>
  <div class="card">
  {{if .HasFindings}}
    <table>
      <thead><tr><th>Уровень</th><th>Правило</th><th>Где</th><th>Что</th></tr></thead>
      <tbody>
      {{range .Findings}}
        <tr>
          <td class="sev sev-{{.Severity}}">{{.Label}}{{if .Blocking}}<div class="blocking">блокирует</div>{{end}}</td>
          <td><code>{{.RuleID}}</code></td>
          <td><code>{{.File}}</code><div class="loc">строка {{.Line}}</div></td>
          <td>{{.Message}}{{if .Matched}}<pre>{{.Matched}}</pre>{{end}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  {{else if .Scan.Completed}}
    <p class="empty">Сканер отработал, срабатываний нет.</p>
  {{else}}
    <p class="empty">Прогон не состоялся — находок нет не потому, что пакет чист.
    Решение по пакету принимает DevSecOps вручную.</p>
  {{end}}
  </div>

  <footer>
    Сформировано {{.GeneratedLocal}} · схема <code>{{.Schema}}</code>
    {{if .ItemID}} · пакет заявки #{{.ItemID}}{{end}}{{if .RequestID}} · заявка #{{.RequestID}}{{end}}
  </footer>
</div>
</body>
</html>
`))
