// Package reports — отчёты о прогоне сканеров содержимого.
//
// Зачем отдельный артефакт, если находки и так лежат в таблице code_finding:
// таблица отвечает на вопрос «что показать в карточке заявки прямо сейчас», а
// отчёт — на вопрос «что именно увидел сканер в этом прогоне, по каким
// правилам и в какой версии». Находки в БД перезаписываются на каждом прогоне
// (_store_code_findings в Python-версии удаляет предыдущие), отчёт же остаётся
// снимком: по нему DevSecOps объясняет решение, а разработчик — понимает, что
// чинить. Плюс отчёт — это то, что можно приложить к заявке или унести в CI.
//
// Два формата на один прогон (см. Render):
//   - JSON — машиночитаемый, со схемой и её версией; его читает CI и API;
//   - HTML — самодостаточная страница без внешних ресурсов (CSP на машине
//     заказчика режет всё внешнее, а отчёт должен открываться и из письма, и
//     с диска).
//
// Отчёт строится и для прогона, в котором находок нет, и для прогона, который
// не состоялся (сканер недоступен): «проверка не выполнена» — это результат,
// который обязан быть виден, а не отсутствие файла.
package reports

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"moderation/internal/scanners"
)

// SchemaVersion — версия структуры JSON-отчёта. Потребители (CI) вправе на неё
// ориентироваться, поэтому несовместимое изменение полей обязано её поднять.
const SchemaVersion = "moderation.scan-report/v1"

// Kind — вид проверки. Совпадает с кодом шага конвейера, чтобы отчёт можно
// было однозначно связать с шагом.
type Kind string

const (
	KindSandbox Kind = "sandbox_scan"
	// Виды снятых с конвейера шагов остаются: отчёты, сделанные до снятия,
	// лежат в хранилище и обязаны читаться (см. domain.RetiredStepCodes).
	KindBanner Kind = "banner_scan"
	KindSAST   Kind = "sast_scan"
)

// Title — заголовок вида проверки для человека.
func (k Kind) Title() string {
	switch k {
	case KindSandbox:
		return "Проверка в песочнице"
	// Названия снятых видов остаются прежними: отчёт — снимок прогона, и
	// заголовок в нём отвечает на вопрос «что проверяли», а не «выполняется ли
	// этот шаг сегодня». Пометка о снятии живёт в domain.StepTitles, то есть
	// там, где показывается конвейер.
	case KindBanner:
		return "Политические баннеры"
	case KindSAST:
		return "SAST-анализ"
	default:
		return string(k)
	}
}

// Package — что проверяли.
type Package struct {
	Manager     string `json:"manager"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	DisplayName string `json:"display_name,omitempty"`
	Artifact    string `json:"artifact,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

// Ref — человеческая запись пакета: то, что видно в заголовке отчёта.
func (p Package) Ref() string {
	name := p.DisplayName
	if name == "" {
		name = p.Name
	}
	return fmt.Sprintf("%s %s (%s)", name, p.Version, p.Manager)
}

// Scan — чем и как проверяли.
type Scan struct {
	Kind      Kind   `json:"kind"`
	Title     string `json:"title"`
	Scanner   string `json:"scanner"`
	Rules     string `json:"rules,omitempty"`
	Threshold string `json:"threshold"`
	// Completed=false — проверка НЕ состоялась. Это не «чисто»: шаг обязан в
	// таком случае позвать DevSecOps, а отчёт — явно об этом сказать.
	Completed  bool      `json:"completed"`
	Detail     string    `json:"detail"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Unpacked — что удалось разложить: если распаковка была ограничена, часть
// содержимого не проверена, и отчёт обязан это показать, иначе «находок нет»
// читается как «пакет чист».
type Unpacked struct {
	Files         int      `json:"files"`
	TotalBytes    int64    `json:"total_bytes"`
	SkippedUnsafe int      `json:"skipped_unsafe"`
	SkippedLarge  int      `json:"skipped_large"`
	Truncated     bool     `json:"truncated"`
	Notes         []string `json:"notes,omitempty"`
}

// Summary — сводка, чтобы не считать её заново в каждом потребителе.
type Summary struct {
	Total          int            `json:"total"`
	Blocking       int            `json:"blocking"`
	WorstSeverity  string         `json:"worst_severity,omitempty"`
	BySeverity     map[string]int `json:"by_severity"`
	RulesTriggered []string       `json:"rules_triggered"`
	FilesAffected  int            `json:"files_affected"`
}

// Report — отчёт об одном прогоне одного сканера по одному пакету.
type Report struct {
	Schema      string    `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	RequestID   int64     `json:"request_id,omitempty"`
	ItemID      int64     `json:"request_item_id,omitempty"`

	Package  Package            `json:"package"`
	Scan     Scan               `json:"scan"`
	Unpacked Unpacked           `json:"unpacked"`
	Summary  Summary            `json:"summary"`
	Findings []scanners.Finding `json:"findings"`
	Decision *Decision          `json:"decision,omitempty"`
}

// Decision — решение DevSecOps, если оно уже вынесено на момент построения
// отчёта (security_override). Без этого поля отчёт по одобренному вручную
// пакету выглядел бы как необъяснённо проигнорированные находки.
type Decision struct {
	Kind      string    `json:"kind"`
	DecidedBy string    `json:"decided_by"`
	DecidedAt time.Time `json:"decided_at"`
	Comment   string    `json:"comment,omitempty"`
}

// Input — всё, из чего собирается отчёт.
type Input struct {
	Package   Package
	Kind      Kind
	Scanner   string
	Rules     string
	Threshold string
	Outcome   scanners.Outcome
	Unpacked  Unpacked
	RequestID int64
	ItemID    int64
	StartedAt time.Time
	EndedAt   time.Time
	Decision  *Decision
	// Now подменяется в тестах; nil — time.Now.
	Now func() time.Time
}

// Build собирает отчёт. Порог пустой означает "info" — пропускаются все
// находки (так устроен шаг баннеров: совпадение правила само по себе находка).
func Build(in Input) *Report {
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	threshold := in.Threshold
	if strings.TrimSpace(threshold) == "" {
		threshold = "info"
	}

	findings := append([]scanners.Finding(nil), in.Outcome.Findings...)
	blocking := in.Outcome.AboveThreshold(threshold)

	bySeverity := map[string]int{}
	rules := map[string]struct{}{}
	files := map[string]struct{}{}
	for _, f := range findings {
		bySeverity[f.Severity]++
		rules[f.RuleID] = struct{}{}
		files[f.File] = struct{}{}
	}
	ruleList := make([]string, 0, len(rules))
	for rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Strings(ruleList)

	var duration int64
	if !in.StartedAt.IsZero() && !in.EndedAt.IsZero() {
		duration = in.EndedAt.Sub(in.StartedAt).Milliseconds()
	}

	return &Report{
		Schema:      SchemaVersion,
		GeneratedAt: now().UTC(),
		RequestID:   in.RequestID,
		ItemID:      in.ItemID,
		Package:     in.Package,
		Scan: Scan{
			Kind:       in.Kind,
			Title:      in.Kind.Title(),
			Scanner:    in.Scanner,
			Rules:      in.Rules,
			Threshold:  threshold,
			Completed:  in.Outcome.Available,
			Detail:     in.Outcome.Detail,
			DurationMs: duration,
			StartedAt:  in.StartedAt.UTC(),
			FinishedAt: in.EndedAt.UTC(),
		},
		Unpacked: in.Unpacked,
		Summary: Summary{
			Total:          len(findings),
			Blocking:       len(blocking),
			WorstSeverity:  in.Outcome.WorstSeverity(),
			BySeverity:     bySeverity,
			RulesTriggered: ruleList,
			FilesAffected:  len(files),
		},
		Findings: findings,
		Decision: in.Decision,
	}
}

// JSON — машиночитаемый отчёт.
//
// SetEscapeHTML(false) важен: иначе кириллица остаётся читаемой, а вот `<`,
// `>` и `&` в совпавшем фрагменте кода превращаются в < — отчёт по
// JS-пакету становится нечитаемым и, что хуже, неграпаемым. Ровно та же мина,
// что с json_ensure_ascii в логах Python-версии (см. handoff, п. 8.4).
func (r *Report) JSON() ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, fmt.Errorf("сериализация отчёта: %w", err)
	}
	return []byte(buf.String()), nil
}

// Verdict — короткая формулировка итога прогона для человека. Один и тот же
// текст в HTML-отчёте и в сообщении шага, чтобы они не расходились.
func (r *Report) Verdict() string {
	if !r.Scan.Completed {
		return "Проверка не выполнена — решение принимает DevSecOps"
	}
	if r.Summary.Blocking > 0 {
		return fmt.Sprintf("Найдено срабатываний выше порога: %d — требуется решение DevSecOps",
			r.Summary.Blocking)
	}
	if r.Summary.Total > 0 {
		return fmt.Sprintf("Срабатываний выше порога «%s» нет (ниже порога: %d)",
			r.Scan.Threshold, r.Summary.Total)
	}
	return "Срабатываний нет"
}

// State — состояние прогона одним словом: определяет цвет плашки в HTML и
// удобно для фильтрации в CI.
func (r *Report) State() string {
	switch {
	case !r.Scan.Completed:
		return "unavailable"
	case r.Summary.Blocking > 0:
		return "findings"
	default:
		return "clean"
	}
}

// FileName — имя файла отчёта. Расширение задаёт формат ("json" | "html").
func (r *Report) FileName(ext string) string {
	safe := func(s string) string {
		s = strings.TrimSpace(s)
		var b strings.Builder
		for _, c := range s {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
				c == '-', c == '.', c == '_':
				b.WriteRune(c)
			default:
				b.WriteRune('_')
			}
		}
		return b.String()
	}
	return fmt.Sprintf("%s-%s-%s.%s",
		string(r.Scan.Kind), safe(r.Package.Name), safe(r.Package.Version), ext)
}
