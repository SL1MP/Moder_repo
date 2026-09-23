package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"moderation/internal/domain"
	"moderation/internal/reports"
	"moderation/internal/sandbox"
	"moderation/internal/scanners"
)

// --------------------------------------------------------------------------- шаг 6
// SandboxScanStep — динамический анализ артефакта в песочнице.
//
// Отличие от снятых сканеров содержимого: те обходили распакованные файлы
// своими правилами, а этот отдаёт архив целиком внешней системе, которая
// запускает его по-настоящему и возвращает вердикт. Поэтому шаг не
// contentScanStep: распаковывать нечего, и порога серьёзности у него нет —
// решение принимает песочница, а не мы по числу находок.
//
// Соответствие вердикта и исхода шага:
//
//	CLEAN      → pass   публикация продолжается
//	UNWANTED   → info   пометка в карточке и отчёте, публикацию НЕ держит
//	DANGEROUS  → fail   публикация заблокирована, решает DevSecOps
//	иное/нет   → warn   вердикт неизвестен или песочница не ответила — DevSecOps
//
// UNWANTED не блокирует по решению пользователя: это «нежелательное», а не
// «вредоносное», и держать на нём публикацию значило бы звать DevSecOps на
// каждый пакет с рекламным SDK внутри.
//
// DANGEROUS не отклоняет пакет сам, а зовёт DevSecOps — как и проверка
// уязвимостей. Причина та же: у ложного срабатывания песочницы обязан быть
// выход, иначе единственным способом опубликовать пакет остаётся выключить шаг
// целиком. Публикация при этом заблокирована в обоих случаях: пока решение не
// принято, PublishStep видит непогашенную блокировку (blockers.go).
type SandboxScanStep struct{}

func (SandboxScanStep) Code() string { return "sandbox_scan" }

// sandboxTitle — как шаг называется в сообщениях. Тот же текст, что в
// domain.StepTitles: расхождение между карточкой и сообщением шага читается
// как два разных шага.
const sandboxTitle = "Проверка в песочнице"

func (s SandboxScanStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	if !pc.Config.SandboxEnabled {
		// Чистое выключение: шаг отдаёт pass с явной пометкой, а не молча
		// пропускается. Отчёт при этом не пишется — прогона не было.
		return Pass("Шаг выключен настройкой (SANDBOX_ENABLED)."), nil
	}

	artifact, err := pc.Deps.Repo.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if artifact == nil {
		return Fail("Артефакт для отправки в песочницу не найден — шаг скачивания не выполнен.").
			WithStatus("failed", "failed").
			WithNextAction("Перезапустите проверку заявки."), nil
	}

	run := sandboxRun{
		filename:  artifact.Filename,
		sha256:    deref(artifact.SHA256),
		startedAt: pc.now(),
	}

	client := pc.Deps.Sandbox
	switch {
	case client == nil || !client.Available():
		run.detail = "песочница не настроена (SANDBOX_URL не задан)"
	default:
		payload, err := pc.Payload(ctx, artifact)
		if err != nil {
			return StepOutcome{}, err
		}
		run.endpoint = client.Endpoint()
		result, checkErr := client.Check(ctx, artifact.Filename, payload)
		if checkErr != nil {
			run.detail = checkErr.Error()
		} else {
			run.available = true
			run.result = result
			run.detail = describe(result)
		}
	}
	run.finishedAt = pc.now()

	return s.finish(ctx, pc, run)
}

// sandboxRun — всё, что известно об одном обращении к песочнице. Собирается в
// одном месте, чтобы ветка «не ответила» и ветка «ответила» дальше шли общим
// кодом: отчёт обязан появиться в обоих случаях.
type sandboxRun struct {
	filename   string
	sha256     string
	endpoint   string
	available  bool
	detail     string
	result     sandbox.Result
	startedAt  time.Time
	finishedAt time.Time
}

func (s SandboxScanStep) finish(ctx context.Context, pc *Context, run sandboxRun) (StepOutcome, error) {
	outcome := scanners.Outcome{
		Available: run.available,
		Detail:    run.detail,
		Findings:  findingsOf(run.result),
	}

	if err := storeSandboxFindings(ctx, pc, outcome); err != nil {
		return StepOutcome{}, err
	}

	report := reports.Build(reports.Input{
		Package: reports.Package{
			Manager: pc.Package.Manager, Name: pc.Package.Name,
			Version: pc.Version.RawVersion, DisplayName: pc.Package.DisplayName,
			Artifact: run.filename, SHA256: run.sha256,
		},
		Kind:    reports.KindSandbox,
		Scanner: scannerName(run.endpoint),
		// Порога у песочницы нет: блокирует вердикт, а не число находок. «info»
		// означает «в сводку идут все находки» — прятать часть из них под
		// порогом, который ни на что не влияет, было бы обманом.
		Threshold: "info",
		Outcome:   outcome,
		// Unpacked пустой намеренно: архив уходит в песочницу целиком, ничего
		// не распаковывается. Примечание объясняет это прямо, иначе нули в
		// отчёте читаются как «распаковали и ничего не нашли».
		Unpacked: reports.Unpacked{Notes: []string{
			"Артефакт отправлен в песочницу целиком, без распаковки на нашей стороне.",
		}},
		RequestID: pc.Item.RequestID,
		ItemID:    pc.Item.ID,
		StartedAt: run.startedAt,
		EndedAt:   run.finishedAt,
		Decision:  overrideToDecision(pc.SecurityOverride),
		Now:       pc.now,
	})

	keys, reportErr := saveScanReport(ctx, pc, s.Code(), report)
	// Отчёт — не условие прохождения шага: если хранилище недоступно, вердикт
	// песочницы всё равно вынесен, и терять его из-за отчёта нельзя. Но
	// умолчать тоже нельзя — недоступность попадает в сообщение шага.
	reportNote := ""
	if reportErr != nil {
		reportNote = fmt.Sprintf(" Отчёт не сохранён: %v.", reportErr)
	}

	details := map[string]any{
		"detail": run.detail,
		"state":  report.State(),
	}
	if run.endpoint != "" {
		details["sandbox_url"] = run.endpoint
	}
	if reportErr == nil {
		details["report_json"] = keys.json
		details["report_html"] = keys.html
	}
	// Счётчики и ссылка на задачу — только по состоявшемуся прогону. Ноль по
	// непрошедшей проверке не измерение, а его отсутствие, и в карточке он
	// читается ровно наоборот («проверили, ничего нет») — тот же урок, что со
	// счётчиком уязвимостей.
	if run.available {
		details["verdict"] = run.result.Verdict
		details["findings_total"] = report.Summary.Total
		if run.result.ScanID != "" {
			details["scan_id"] = run.result.ScanID
		}
		if run.result.TaskURL != "" {
			details["task_url"] = run.result.TaskURL
		}
	}

	return s.verdictOutcome(pc, run, report, details, reportNote), nil
}

// verdictOutcome — превращение вердикта песочницы в исход шага.
func (s SandboxScanStep) verdictOutcome(
	pc *Context, run sandboxRun, report *reports.Report,
	details map[string]any, reportNote string,
) StepOutcome {
	// Явное разрешение DevSecOps важнее вердикта шага — как и в проверке
	// уязвимостей: иначе возобновлённый конвейер снова упёрся бы в тот же
	// вердикт, и решение не имело бы эффекта.
	//
	// «Разрешено вручную» и «песочница не ответила» при этом не смешиваются:
	// во втором случае сообщение прямо говорит, что проверки не было.
	if pc.SecurityOverride != nil {
		details["reason"] = "security_override"
		details["decided_by"] = pc.SecurityOverride.DecidedBy
		verdict := fmt.Sprintf("Вердикт песочницы: %s.", run.result.Verdict)
		if !run.available {
			details["sandbox_unavailable"] = run.detail
			verdict = fmt.Sprintf(
				"ВНИМАНИЕ: проверка не выполнялась (%s), поэтому отсутствие находок "+
					"ничего не означает.", run.detail)
		}
		return Pass(fmt.Sprintf("%s: публикация разрешена вручную (%s). %s%s",
			sandboxTitle, pc.SecurityOverride.DecidedBy, verdict, reportNote)).
			WithDetails(details)
	}

	if !run.available {
		details["reason"] = "sandbox_unavailable"
		return Warn(fmt.Sprintf(
			"%s: проверка не выполнена (%s). Автоматическое одобрение по этому шагу отключено.%s",
			sandboxTitle, run.detail, reportNote)).
			WithDetails(details).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("Дождитесь решения DevSecOps: песочница не вынесла вердикт, "+
				"решение принимается вручную.").
			WithNotify(EventAwaitsSecurity, "devsecops")
	}

	found := ""
	if report.Summary.Total > 0 {
		found = fmt.Sprintf(" Находок: %d (%s).",
			report.Summary.Total, joinComma(limitStrings(report.Summary.RulesTriggered, 20)))
	}
	task := ""
	if run.result.TaskURL != "" {
		task = " Задача в песочнице: " + run.result.TaskURL + "."
	}

	switch run.result.Verdict {
	case sandbox.VerdictClean:
		return Pass(fmt.Sprintf("%s: вердикт CLEAN — вредоносного поведения не обнаружено.%s%s",
			sandboxTitle, task, reportNote)).WithDetails(details)

	case sandbox.VerdictUnwanted:
		// Информационный исход: пометка есть, публикацию не держит.
		details["reason"] = "unwanted"
		details["advisory"] = true
		return Info(fmt.Sprintf(
			"%s: вердикт UNWANTED — песочница отнесла содержимое к нежелательному. "+
				"Публикацию шаг не блокирует, находки смотрите в отчёте.%s%s%s",
			sandboxTitle, found, task, reportNote)).WithDetails(details)

	case sandbox.VerdictDangerous:
		details["reason"] = "dangerous"
		return Fail(fmt.Sprintf(
			"%s: вердикт DANGEROUS — публикация заблокирована.%s%s%s",
			sandboxTitle, found, task, reportNote)).
			WithDetails(details).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("Публикация остановлена: песочница нашла вредоносное поведение. "+
				"Посмотрите отчёт в карточке пакета — решение принимает DevSecOps.").
			WithNotify(EventAwaitsSecurity, "devsecops")

	default:
		// Незнакомый вердикт не «чисто»: пропустить пакет по значению, смысла
		// которого мы не знаем, нельзя.
		details["reason"] = "unknown_verdict"
		return Warn(fmt.Sprintf(
			"%s: песочница вернула вердикт %q, который сервису неизвестен. "+
				"Публикация остановлена до решения DevSecOps.%s%s",
			sandboxTitle, run.result.Verdict, task, reportNote)).
			WithDetails(details).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("Сообщите администратору сервиса: песочница отвечает значением, "+
				"которого нет в списке известных вердиктов.").
			WithNotify(EventAwaitsSecurity, "devsecops")
	}
}

// storeSandboxFindings перезаписывает находки песочницы для версии пакета —
// тем же способом, что сканеры содержимого: таблица отвечает на вопрос «что
// показать в карточке сейчас», отчёт — «что было в этом прогоне».
func storeSandboxFindings(ctx context.Context, pc *Context, outcome scanners.Outcome) error {
	findings := outcome.Findings
	if len(findings) > 500 {
		findings = findings[:500]
	}
	rows := make([]domain.CodeFinding, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, domain.CodeFinding{
			PackageVersionID: pc.Version.ID,
			Scanner:          f.Scanner,
			RuleID:           f.RuleID,
			Severity:         f.Severity,
			Message:          nilIfEmpty(f.Message),
		})
	}
	return pc.Deps.Repo.ReplaceCodeFindings(ctx, pc.Version.ID, "sandbox", rows)
}

// describe — человеческое описание того, что ответила песочница.
func describe(result sandbox.Result) string {
	verdict := result.Verdict
	if verdict == "" {
		verdict = "не указан"
	}
	detail := fmt.Sprintf("песочница вернула вердикт %s", verdict)
	if result.ScanID != "" {
		detail += fmt.Sprintf(", задача %s", result.ScanID)
	}
	if n := len(result.Detections); n > 0 {
		detail += fmt.Sprintf(", находок: %d", n)
	}
	return detail
}

// scannerName — чем проверяли, для отчёта. Адрес песочницы, а не просто
// «sandbox»: инсталляций бывает несколько, и по отчёту должно быть понятно,
// какая вынесла вердикт.
func scannerName(endpoint string) string {
	if endpoint == "" {
		return "sandbox"
	}
	return "sandbox (" + endpoint + ")"
}

// findingsOf переводит находки песочницы в общий вид находок, чтобы отчёт и
// таблица находок в карточке собирались тем же кодом, что для остальных
// проверок.
//
// Серьёзность песочница присылает не всегда; в этом случае ставим high, а не
// info: находка динамического анализа — это то, что образец сделал при
// запуске, и прятать её ниже порога по умолчанию неправильно.
func findingsOf(result sandbox.Result) []scanners.Finding {
	out := make([]scanners.Finding, 0, len(result.Detections))
	for _, d := range result.Detections {
		severity := strings.ToLower(strings.TrimSpace(d.Severity))
		if !scanners.KnownSeverity(severity) {
			severity = "high"
		}
		rule := firstNonEmpty(d.Name, d.Type, "detection")
		out = append(out, scanners.Finding{
			Scanner:  "sandbox",
			RuleID:   rule,
			Severity: severity,
			Message:  strings.Join(nonEmpty(d.Type, d.Details), ": "),
		})
	}
	return out
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
