// Package requests — разбор входа заявки и её создание.
// Порт backend/app/services/requests_service.py.
//
// Разбор отделён от создания намеренно: по разобранному результату строится и
// ответ на создание заявки, и предварительная проверка «что будет, если я это
// заведу» — а ходить в базу на запись ради второго не нужно.
package requests

import (
	"context"
	"fmt"
	"path"
	"strings"

	"moderation/internal/depfile"
	"moderation/internal/domain"
	"moderation/internal/registry"
	"moderation/internal/repo"
	"moderation/internal/resolve"
)

// Состояния разобранного пакета.
const (
	StateNew           = "new"
	StateAlreadyInBase = "already_in_base"
	StateInvalidFormat = "invalid_format"
)

// transitiveWarning — что увидит автор, когда в файле есть транзитивные
// записи, а раскрытие не просили. Текст «зависимости не подтягиваются»
// больше не годится: подтягиваются, если попросить, — и человек должен знать,
// что у него есть выбор, а не думать, что сервис так не умеет.
const transitiveWarning = "Заявка заведена только по прямым зависимостям. " +
	"Чтобы завести и то, что они тянут за собой, включите раскрытие транзитивных " +
	"зависимостей — сервис построит дерево по данным реестра."

// Parsed — одна запись после разбора.
type Parsed struct {
	Raw   string
	State string
	Ref   *registry.Ref

	DependencyKind string
	// Key и ParentKey связывают записи в дерево зависимостей: ключ узла и
	// ключ того, кто его затребовал. У заявленного пакета ParentKey пуст.
	Key       string
	ParentKey string
	// Depth — 0 у заявленного пакета, 1 у его прямой зависимости и так далее.
	Depth int
	// RequiredRange — требование родителя, по которому выбрана версия.
	RequiredRange     string
	Message           string
	ExpectedFormat    string
	ExistingVersionID *int64
	ExistingStatus    string
	InstallCommand    string
}

// ParseResult — итог разбора входа заявки.
type ParseResult struct {
	Manager  string
	Packages []Parsed
	Warnings []string
}

// New — записи, по которым заводятся пакеты заявки.
func (r ParseResult) New() []Parsed {
	var out []Parsed
	for _, p := range r.Packages {
		if p.State == StateNew {
			out = append(out, p)
		}
	}
	return out
}

// Input — вход заявки: либо перечисление, либо файл зависимостей.
type Input struct {
	Manager string
	// Entries — записи в краткой форме («requests==2.31.0»).
	Entries []string
	// Structured — записи в объектной форме {name, version}.
	Structured []NameVersion
	// Filename и Content — файл зависимостей.
	Filename string
	Content  []byte
	// IncludeTransitive — раскрывать ли транзитивные зависимости: брать их из
	// файла, если он их перечисляет, и достраивать дерево по данным реестра.
	IncludeTransitive bool
	// ResolveDepth — глубина раскрытия. 0 — взять из настроек сервиса.
	ResolveDepth int
	// Reason — зачем пакет нужен. Читается вместе с остальным входом, хотя
	// разбору не нужен: способов передать его два, и разбирать их дважды —
	// верный способ однажды потерять его в одном из них.
	Reason string
}

// NameVersion — объектная форма записи.
type NameVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Limits — ограничения на заявку.
type Limits struct {
	MaxPackages   int
	MaxUploadSize int64
}

// Service — разбор и создание заявок.
type Service struct {
	Repo     *repo.Repo
	Registry *registry.Registry
	Limits   Limits
	// Resolver раскрывает транзитивные зависимости. nil — раскрытие
	// выключено: сервис обязан работать и без похода в реестр за графом.
	Resolver *resolve.Resolver
	// InstallCommand собирает команду установки для уже одобренного пакета.
	// Функцией, а не зависимостью от конфига: сервису нужен один вызов, а не
	// весь конфиг артефактори.
	InstallCommand func(manager, name, displayName, version, rawVersion string) string
	// OnAuditError зовётся, когда запись аудита не удалась. Заявка при этом
	// уже создана, и отменять её из-за журнала нельзя — но и молчать нельзя.
	OnAuditError func(error)
}

// ErrValidation — вход некорректен (422). ErrLimit — превышен предел (413).
// ErrEmpty — разбирать нечего (404, как у python-версии).
var (
	ErrValidation = fmt.Errorf("некорректный вход заявки")
	ErrLimit      = fmt.Errorf("превышен предел")
	ErrEmpty      = fmt.Errorf("в запросе не найдено ни одного пакета для модерации")
)

// indeterminateKindFiles — файлы, в которых прямые и транзитивные зависимости
// неразличимы. Записи из них считаются прямыми, а пользователь получает
// предупреждение: иначе фильтр транзитивных выбросил бы весь файл.
var indeterminateKindFiles = map[string][]string{
	"go": {"go.sum"},
	// poetry.lock и yarn.lock перечисляют закрытый набор, но не говорят, что
	// из него прямое: в poetry.lock нет такого поля вовсе, в yarn.lock
	// заголовок записи — это спецификатор, а не роль. Раньше все записи
	// помечались транзитивными, и заявка по такому файлу без галочки
	// приезжала ПУСТОЙ — фильтр выбрасывал весь файл.
	"pypi": {"poetry.lock"},
	"npm":  {"yarn.lock"},
}

// Parse разбирает вход и помечает каждую запись: new, already_in_base или
// invalid_format.
func (s *Service) Parse(ctx context.Context, in Input) (ParseResult, error) {
	plugin, err := s.Registry.Get(in.Manager)
	if err != nil {
		return ParseResult{}, fmt.Errorf("%w: %s", ErrValidation, err)
	}
	result := ParseResult{Manager: plugin.Code()}

	entries, warnings, err := s.collect(plugin, in)
	if err != nil {
		return ParseResult{}, err
	}
	result.Warnings = warnings

	if len(entries) == 0 {
		return ParseResult{}, ErrEmpty
	}
	maxPackages := s.Limits.MaxPackages
	if maxPackages <= 0 {
		maxPackages = 200
	}
	if len(entries) > maxPackages {
		return ParseResult{}, fmt.Errorf("%w: в заявке %d пакетов, максимум %d",
			ErrLimit, len(entries), maxPackages)
	}

	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.Ref == nil {
			result.Packages = append(result.Packages, Parsed{
				Raw: entry.Raw, State: StateInvalidFormat,
				Message: entry.Err, ExpectedFormat: valueOr(entry.Format, plugin.EntryFormat()),
			})
			continue
		}
		key := entry.Ref.Name + "\x00" + entry.Ref.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		parsed, err := s.classify(ctx, *entry.Ref, entry.Raw, entry.Kind)
		if err != nil {
			return ParseResult{}, err
		}
		result.Packages = append(result.Packages, parsed)
	}
	return result, nil
}

// entry — промежуточное представление записи до сверки с базой.
type entry struct {
	Raw    string
	Ref    *registry.Ref
	Kind   string
	Err    string
	Format string
}

// collect приводит оба способа задания пакетов к одному списку.
func (s *Service) collect(plugin registry.Plugin, in Input) ([]entry, []string, error) {
	if in.Content != nil {
		return s.fromFile(plugin, in)
	}

	var out []entry
	for _, row := range in.Structured {
		name, version := strings.TrimSpace(row.Name), strings.TrimSpace(row.Version)
		raw := strings.TrimSpace(name + " " + version)
		ref, err := registry.MakeRef(plugin, name, version)
		if err != nil {
			out = append(out, entry{Raw: raw, Err: err.Error(), Format: plugin.EntryFormat()})
			continue
		}
		out = append(out, entry{Raw: raw, Ref: &ref, Kind: depfile.KindDirect})
	}
	for _, raw := range in.Entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ref, err := registry.ParseEntry(plugin, raw)
		if err != nil {
			out = append(out, entry{Raw: raw, Err: err.Error(), Format: plugin.EntryFormat()})
			continue
		}
		out = append(out, entry{Raw: raw, Ref: &ref, Kind: depfile.KindDirect})
	}
	return out, nil, nil
}

// fromFile разбирает файл зависимостей.
func (s *Service) fromFile(plugin registry.Plugin, in Input) ([]entry, []string, error) {
	limit := s.Limits.MaxUploadSize
	if limit > 0 && int64(len(in.Content)) > limit {
		return nil, nil, fmt.Errorf("%w: файл больше допустимого размера %d байт", ErrLimit, limit)
	}
	deps, err := depfile.Parse(plugin.Code(), in.Filename, in.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}

	var warnings []string
	if isIndeterminateKind(plugin.Code(), in.Filename) {
		// Формат не различает прямые и транзитивные — значит фильтровать
		// нечего: все записи принимаются как прямые. Иначе фильтр выбросил бы
		// ВЕСЬ файл, и заявка приехала бы пустой (живой случай poetry.lock).
		for i := range deps {
			deps[i].Kind = depfile.KindDirect
		}
		warnings = append(warnings, fmt.Sprintf(
			"Файл «%s» перечисляет закрытый набор зависимостей и не различает прямые и "+
				"транзитивные — формат такого поля не имеет. Приняты все записи; "+
				"лишние удалите из заявки вручную.",
			in.Filename))
	}

	hasTransitive := false
	for _, dep := range deps {
		if dep.Kind == depfile.KindTransitive {
			hasTransitive = true
			break
		}
	}
	if hasTransitive {
		warnings = append(warnings, transitiveWarning)
		if !in.IncludeTransitive {
			kept := deps[:0]
			skipped := 0
			for _, dep := range deps {
				if dep.Kind == depfile.KindTransitive {
					skipped++
					continue
				}
				kept = append(kept, dep)
			}
			deps = kept
			warnings = append(warnings, fmt.Sprintf(
				"Транзитивных зависимостей в файле: %d. Они пропущены (include_transitive=false).",
				skipped))
		}
	}

	out := make([]entry, 0, len(deps))
	for _, dep := range deps {
		raw := strings.TrimSpace(dep.Name + " " + dep.Version)
		if dep.Version == "" {
			// Версия не закреплена: запись не отбрасывается молча — объяснение
			// из парсера уходит пользователю как есть.
			out = append(out, entry{Raw: raw, Err: valueOr(dep.Note,
				"Для «"+dep.Name+"» не указана точная версия"), Format: plugin.EntryFormat()})
			continue
		}
		ref, err := registry.MakeRef(plugin, dep.Name, dep.Version)
		if err != nil {
			out = append(out, entry{Raw: raw, Err: err.Error(), Format: plugin.EntryFormat()})
			continue
		}
		out = append(out, entry{Raw: raw, Ref: &ref, Kind: valueOr(dep.Kind, depfile.KindDirect)})
	}
	return out, warnings, nil
}

// classify сверяет запись с базой: уже одобрен, запрещён или новый.
func (s *Service) classify(ctx context.Context, ref registry.Ref, raw, kind string) (Parsed, error) {
	parsed := Parsed{Raw: raw, State: StateNew, Ref: &ref,
		DependencyKind: valueOr(kind, depfile.KindDirect), Key: resolve.Key(ref)}

	existing, err := s.Repo.FindVersion(ctx, ref.Manager, ref.Name, ref.Version)
	if err != nil {
		return Parsed{}, err
	}
	if existing == nil {
		return parsed, nil
	}
	parsed.ExistingVersionID = &existing.ID
	parsed.ExistingStatus = existing.Status

	switch existing.Status {
	case "approved":
		// Уже одобренные в заявку не попадают: заводить вторую заявку на то,
		// что можно ставить прямо сейчас, — пустая работа для всех ролей.
		parsed.State = StateAlreadyInBase
		parsed.Message = fmt.Sprintf("%s %s уже одобрен — заявка по нему не требуется.",
			ref.DisplayName, ref.RawVersion)
		if s.InstallCommand != nil {
			parsed.InstallCommand = s.InstallCommand(
				ref.Manager, ref.Name, ref.DisplayName, ref.Version, ref.RawVersion)
		}
	case "blacklisted", "revoked", "rejected":
		parsed.State = StateAlreadyInBase
		reason := ""
		if existing.StatusReason != nil {
			reason = *existing.StatusReason
		}
		parsed.Message = strings.TrimSpace(fmt.Sprintf("%s %s: %s. %s",
			ref.DisplayName, ref.RawVersion, statusTitle(existing.Status), reason))
	}
	return parsed, nil
}

func isIndeterminateKind(manager, filename string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(filename, `\`, "/")))
	for _, pattern := range indeterminateKindFiles[manager] {
		if ok, err := path.Match(pattern, base); err == nil && ok {
			return true
		}
	}
	return false
}

func statusTitle(status string) string {
	if title, ok := domain.StatusTitles[status]; ok {
		return title
	}
	return status
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
