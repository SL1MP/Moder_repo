package pipeline

import (
	"context"
	"fmt"
	"strings"

	"moderation/internal/domain"
	"moderation/internal/reports"
	"moderation/internal/scanners"
	"moderation/internal/storage"
	"moderation/internal/unpack"
)

// --------------------------------------------------------------------------- шаги 6–7
// contentScanStep — общая часть сканеров содержимого: распаковка, прогон,
// разбор находок, сохранение отчёта.
//
// Блокирующий сканер отдаёт решение DevSecOps, а не отклоняет пакет сам:
// политический баннер — повод посмотреть глазами, а не безусловный запрет.
// Конвейер при этом не останавливается (Pending), чтобы DevSecOps увидел все
// находки разом, а не по одной за прогон.
//
// Информационный сканер (advisory) не блокирует публикацию вообще — см. поле.
type contentScanStep struct {
	code      string
	title     string
	kind      reports.Kind
	scanner   func(pc *Context) scanners.Scanner
	enabled   func(cfg Config) bool
	threshold func(cfg Config) string
	// advisory — шаг информационный: находки сохраняются и попадают в отчёт,
	// но публикацию не задерживают и решения роли не требуют.
	//
	// Так устроен SAST. Причина в природе находок: semgrep на исходниках
	// библиотеки размечает eval/exec, которые для половины пакетов —
	// нормальная работа, а не закладка. Блокирующий SAST означал бы, что
	// DevSecOps вручную подтверждает каждый второй пакет, и подтверждение
	// перестаёт быть решением. Политические баннеры — обратный случай:
	// совпадение правила там само по себе повод не публиковать, поэтому
	// баннерный шаг блокирующий.
	//
	// Находки при этом никуда не деваются: таблица находок в карточке, отчёт
	// JSON/HTML и строка scan_report заполняются одинаково для обоих видов.
	advisory bool
	// enabledSetting — имя настройки для сообщения о выключенном шаге.
	enabledSetting string
	// rules — какой набор правил применялся; попадает в отчёт.
	rules func(pc *Context) string
}

func (s contentScanStep) Code() string { return s.code }

func (s contentScanStep) Run(ctx context.Context, pc *Context) (StepOutcome, error) {
	if !s.enabled(pc.Config) {
		// Чистое выключение: шаг отдаёт pass с явной пометкой, а не молча
		// пропускается. Отчёт при этом не пишется — прогона не было.
		return Pass(fmt.Sprintf("Шаг выключен настройкой (%s).", s.enabledSetting)), nil
	}

	artifact, err := pc.Deps.Repo.CurrentArtifact(ctx, pc.Version.ID)
	if err != nil {
		return StepOutcome{}, err
	}
	if artifact == nil {
		return Fail("Артефакт для сканирования не найден — шаг скачивания не выполнен.").
			WithStatus("failed", "failed").
			WithNextAction("Перезапустите проверку заявки."), nil
	}

	payload, err := pc.Payload(ctx, artifact)
	if err != nil {
		return StepOutcome{}, err
	}

	unpacked, err := unpack.Artifact(payload, artifact.Filename, unpack.Limits{
		MaxTotalBytes: pc.Config.ScanMaxUnpackedBytes,
		MaxFiles:      pc.Config.ScanMaxFiles,
	})
	if err != nil {
		return StepOutcome{}, fmt.Errorf("распаковка артефакта для сканирования: %w", err)
	}
	defer unpack.Cleanup(unpacked)

	startedAt := pc.now()
	outcome, err := s.scanner(pc).Scan(ctx, unpacked.Root)
	if err != nil {
		// Сбой сканера не роняет конвейер: это «проверка не выполнена», то
		// есть повод позвать DevSecOps, а не техническая авария заявки.
		outcome = scanners.Outcome{
			Available: false,
			Detail:    fmt.Sprintf("сканер завершился ошибкой: %v", err),
		}
	}
	finishedAt := pc.now()

	if err := s.storeFindings(ctx, pc, outcome); err != nil {
		return StepOutcome{}, err
	}

	threshold := s.threshold(pc.Config)
	report := reports.Build(reports.Input{
		Package: reports.Package{
			Manager: pc.Package.Manager, Name: pc.Package.Name,
			Version: pc.Version.RawVersion, DisplayName: pc.Package.DisplayName,
			Artifact: artifact.Filename, SHA256: deref(artifact.SHA256),
		},
		Kind:      s.kind,
		Scanner:   s.scanner(pc).Name(),
		Rules:     s.rules(pc),
		Threshold: threshold,
		Outcome:   outcome,
		Unpacked: reports.Unpacked{
			Files: unpacked.Files, TotalBytes: unpacked.TotalBytes,
			SkippedUnsafe: unpacked.SkippedUnsafe, SkippedLarge: unpacked.SkippedLarge,
			Truncated: unpacked.Truncated, Notes: unpacked.Notes,
		},
		RequestID: pc.Item.RequestID,
		ItemID:    pc.Item.ID,
		StartedAt: startedAt,
		EndedAt:   finishedAt,
		Decision:  overrideToDecision(pc.SecurityOverride),
		Now:       pc.now,
	})

	reportKeys, reportErr := s.saveReport(ctx, pc, report)
	// Отчёт — не условие прохождения шага: если хранилище недоступно, вердикт
	// по пакету всё равно вынесен, и терять его из-за отчёта нельзя. Но
	// умолчать тоже нельзя — недоступность попадает в сообщение шага.
	reportNote := ""
	if reportErr != nil {
		reportNote = fmt.Sprintf(" Отчёт не сохранён: %v.", reportErr)
	}

	details := map[string]any{
		"threshold": threshold,
		"detail":    outcome.Detail,
		"notes":     unpacked.Notes,
		"state":     report.State(),
	}
	// Счётчики находок — только когда сканер отработал. Ноль по непрошедшей
	// проверке — не измерение, а отсутствие измерения, и в карточке он читался
	// ровно наоборот: «проверили, ничего нет». Именно так неустановленный
	// semgrep выглядел как чистый пакет.
	//
	// Два числа, а не одно: «нашли 4, выше порога 0» — обычный и важный
	// случай. Ключ не `findings`: под этим именем карточка ждёт список
	// уязвимостей и скрывает поле (см. StepDetails во фронте), из-за чего
	// счётчик не показывался вообще.
	if outcome.Available {
		details["findings_total"] = report.Summary.Total
		details["findings_blocking"] = report.Summary.Blocking
	}
	if reportErr == nil {
		details["report_json"] = reportKeys.json
		details["report_html"] = reportKeys.html
	}

	// Информационный шаг: вердикт ни на что не влияет, поэтому и решение
	// DevSecOps здесь ни при чём — ветка стоит до проверки override. Раньше
	// карточка после разрешения показывала «публикация разрешена вручную,
	// находок: 0», хотя в отчёте по тому же пакету лежали четыре срабатывания:
	// счёт брался из прогона, которого не было.
	if s.advisory {
		return s.advise(outcome, report, threshold, details, reportNote), nil
	}

	// Явное разрешение DevSecOps важнее вердикта шага (см. VulnScanStep).
	//
	// Но «разрешено вручную» и «сканер не отработал» — разные вещи, и
	// смешивать их нельзя. В python-версии эта ветка стоит ДО проверки
	// outcome.available и сообщает «Находок: 0» независимо от того, работал ли
	// сканер вообще: в карточке неустановленный semgrep выглядел как чистый
	// пакет. Здесь недоступность называется прямо, а в отчёте она и так
	// зафиксирована состоянием unavailable.
	if pc.SecurityOverride != nil {
		details["reason"] = "security_override"
		details["decided_by"] = pc.SecurityOverride.DecidedBy
		verdict := fmt.Sprintf("Находок: %d.", report.Summary.Total)
		if !outcome.Available {
			details["scanner_unavailable"] = outcome.Detail
			verdict = fmt.Sprintf(
				"ВНИМАНИЕ: проверка не выполнялась (%s), поэтому отсутствие находок "+
					"ничего не означает.", outcome.Detail)
		}
		return Pass(fmt.Sprintf("%s: публикация разрешена вручную (%s). %s%s",
			s.title, pc.SecurityOverride.DecidedBy, verdict, reportNote)).
			WithDetails(details), nil
	}

	if !outcome.Available {
		// Недоступный сканер — не «чисто». Решает DevSecOps.
		details["reason"] = "scanner_unavailable"
		return Pending(fmt.Sprintf(
			"%s: проверка не выполнена (%s). Автоматическое одобрение по этому шагу отключено.%s",
			s.title, outcome.Detail, reportNote)).
			WithDetails(details).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction(fmt.Sprintf(
				"Дождитесь решения DevSecOps: %s не отработал, вердикт выносится вручную.",
				strings.ToLower(s.title))).
			WithNotify(EventAwaitsSecurity, "devsecops"), nil
	}

	if report.Summary.Blocking > 0 {
		details["reason"] = "findings"
		details["count"] = report.Summary.Blocking
		details["rules"] = report.Summary.RulesTriggered
		return Pending(fmt.Sprintf("%s: найдено срабатываний — %d (правила: %s). "+
			"Требуется решение DevSecOps.%s",
			s.title, report.Summary.Blocking,
			joinComma(limitStrings(report.Summary.RulesTriggered, 20)), reportNote)).
			WithDetails(details).
			WithStatus("awaiting_security", "awaiting_security").
			WithNextAction("Посмотрите находки и отчёт в карточке пакета — решение принимает DevSecOps.").
			WithNotify(EventAwaitsSecurity, "devsecops"), nil
	}

	below := ""
	if report.Summary.Total > 0 {
		below = fmt.Sprintf(" Ниже порога: %d.", report.Summary.Total)
	}
	return Pass(fmt.Sprintf("%s: срабатываний выше порога «%s» нет. %s.%s%s",
		s.title, threshold, outcome.Detail, below, reportNote)).
		WithDetails(details), nil
}

// advise — исход информационного шага. Публикацию не задерживает никогда;
// единственная его задача — честно сказать, что нашли и проверяли ли вообще.
func (s contentScanStep) advise(
	outcome scanners.Outcome, report *reports.Report,
	threshold string, details map[string]any, reportNote string,
) StepOutcome {
	details["advisory"] = true

	if !outcome.Available {
		// «Сканер не отработал» и «чисто» — разные вещи, и для
		// информационного шага это тем более так: pass здесь означал бы
		// «проверено, нет находок», а проверки не было. Позвать DevSecOps
		// нельзя (шаг не блокирующий), поэтому единственная защита от
		// незаметной потери проверки — сказать это в карточке.
		details["reason"] = "scanner_unavailable"
		return Info(fmt.Sprintf(
			"%s: проверка НЕ выполнена (%s), поэтому отсутствие находок ничего не значит. "+
				"Публикацию шаг не блокирует — он информационный.%s",
			s.title, outcome.Detail, reportNote)).WithDetails(details)
	}

	if report.Summary.Total > 0 {
		details["reason"] = "findings"
		details["rules"] = report.Summary.RulesTriggered
		return Info(fmt.Sprintf(
			"%s: найдено срабатываний — %d (выше порога «%s»: %d; правила: %s). "+
				"Публикацию не блокирует — шаг информационный, находки смотрите в отчёте.%s",
			s.title, report.Summary.Total, threshold, report.Summary.Blocking,
			joinComma(limitStrings(report.Summary.RulesTriggered, 20)), reportNote)).
			WithDetails(details)
	}

	return Pass(fmt.Sprintf("%s: срабатываний нет. %s.%s",
		s.title, outcome.Detail, reportNote)).WithDetails(details)
}

// storeFindings перезаписывает находки этого сканера для версии пакета.
func (s contentScanStep) storeFindings(ctx context.Context, pc *Context, outcome scanners.Outcome) error {
	// В карточке всё равно показываем верхушку; 500 — тот же предел, что в
	// Python-версии.
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
			FilePath:         nilIfEmpty(f.File),
			Line:             ptr(f.Line),
			Matched:          nilIfEmpty(f.Matched),
		})
	}
	scannerName := s.scanner(pc).Name()
	return pc.Deps.Repo.ReplaceCodeFindings(ctx, pc.Version.ID, scannerName, rows)
}

type reportKeys struct{ json, html string }

// saveReport кладёт оба файла отчёта в объектное хранилище и пишет строку
// scan_report. Отчёт живёт под префиксом reports/ и переживает вычистку
// артефактов при отклонении пакета — именно им DevSecOps объясняет решение.
func (s contentScanStep) saveReport(ctx context.Context, pc *Context, report *reports.Report) (reportKeys, error) {
	jsonBody, err := report.JSON()
	if err != nil {
		return reportKeys{}, err
	}
	htmlBody, err := report.HTML()
	if err != nil {
		return reportKeys{}, err
	}

	keys := reportKeys{
		json: storage.ReportKey(pc.Item.ID, s.code, "json"),
		html: storage.ReportKey(pc.Item.ID, s.code, "html"),
	}
	if _, err := pc.Deps.Storage.Put(ctx, keys.json, jsonBody, storage.ContentTypeFor("json")); err != nil {
		return reportKeys{}, err
	}
	if _, err := pc.Deps.Storage.Put(ctx, keys.html, htmlBody, storage.ContentTypeFor("html")); err != nil {
		return reportKeys{}, err
	}

	row := domain.ScanReport{
		RequestItemID:    pc.Item.ID,
		PackageVersionID: pc.Version.ID,
		StepCode:         s.code,
		Scanner:          report.Scan.Scanner,
		Rules:            nilIfEmpty(report.Scan.Rules),
		State:            report.State(),
		Threshold:        report.Scan.Threshold,
		FindingsTotal:    report.Summary.Total,
		FindingsBlocking: report.Summary.Blocking,
		WorstSeverity:    nilIfEmpty(report.Summary.WorstSeverity),
		Detail:           nilIfEmpty(report.Scan.Detail),
		JSONKey:          keys.json,
		HTMLKey:          keys.html,
		Bucket:           nilIfEmpty(pc.Deps.Storage.Bucket()),
		DurationMs:       ptr(int(report.Scan.DurationMs)),
	}
	if _, err := pc.Deps.Repo.UpsertScanReport(ctx, row); err != nil {
		return reportKeys{}, err
	}
	return keys, nil
}

func overrideToDecision(o *Override) *reports.Decision {
	if o == nil {
		return nil
	}
	return &reports.Decision{
		Kind: "security_override", DecidedBy: o.DecidedBy,
		DecidedAt: o.DecidedAt, Comment: o.Comment,
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

// BannerScanStep — политические баннеры (YARA). Порога нет: баннер — находка
// сама по себе, любое совпадение правила уходит DevSecOps.
var BannerScanStep = contentScanStep{
	code:           "banner_scan",
	title:          "Политические баннеры",
	kind:           reports.KindBanner,
	scanner:        func(pc *Context) scanners.Scanner { return pc.Deps.Banner },
	enabled:        func(cfg Config) bool { return cfg.BannerScanEnabled },
	threshold:      func(Config) string { return "info" },
	enabledSetting: "BANNER_SCAN_ENABLED",
	rules:          func(pc *Context) string { return rulesOf(pc.Deps.Banner) },
}

// SastScanStep — SAST по исходникам пакета (semgrep).
//
// Информационный: публикацию не блокирует, нужен для отчёта. Почему — см.
// поле advisory в contentScanStep.
var SastScanStep = contentScanStep{
	code:     "sast_scan",
	title:    "SAST-анализ",
	kind:     reports.KindSAST,
	advisory: true,
	scanner:  func(pc *Context) scanners.Scanner { return pc.Deps.SAST },
	enabled:  func(cfg Config) bool { return cfg.SASTEnabled },
	threshold: func(cfg Config) string {
		if cfg.SASTMinSeverity == "" {
			return "medium"
		}
		return cfg.SASTMinSeverity
	},
	enabledSetting: "SAST_ENABLED",
	rules:          func(pc *Context) string { return rulesOf(pc.Deps.SAST) },
}

// rulesOf достаёт применённый набор правил из конкретной реализации сканера —
// для отчёта. Неизвестная реализация не ошибка: поле в отчёте просто пустое.
func rulesOf(s scanners.Scanner) string {
	switch v := s.(type) {
	case scanners.YaraScanner:
		return v.RulesFile
	case *scanners.YaraScanner:
		return v.RulesFile
	case scanners.SemgrepScanner:
		return v.Rules
	case *scanners.SemgrepScanner:
		return v.Rules
	default:
		return ""
	}
}
