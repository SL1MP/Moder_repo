// Package resolve — раскрытие транзитивных зависимостей: из заявленного
// пакета строится дерево того, что он притащит за собой, и каждый узел
// приводится к точной версии.
//
// Зачем это модерации. Уязвимость и запрещённая лицензия приходят в проект
// не через тот пакет, который разработчик вписал в заявку, а через его
// зависимости: заявляют requests, а в сборку попадает ещё четыре пакета,
// которых никто не смотрел. Раскрытие делает этот набор видимым до
// публикации, а не после инцидента.
//
// Чего здесь сознательно нет: разрешения конфликтов версий. Если два пакета
// требуют разные версии одного и того же, обе попадут в результат и будут
// названы конфликтом — выбирать за разработчика, какая из них поедет в
// сборку, сервис не вправе, а молча взять одну значит промодерировать не то.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"moderation/internal/registry"
	"moderation/internal/version"
)

// Node — узел дерева: пакет конкретной версии и то, откуда он взялся.
type Node struct {
	Ref registry.Ref
	// Depth — 0 у заявленного пакета, 1 у его прямых зависимостей и так далее.
	Depth int
	// Parents — все узлы, потребовавшие этот пакет: в дереве зависимостей
	// один пакет приходит несколькими путями, и показать надо все.
	Parents []Edge
}

// Edge — требование одного узла к другому.
type Edge struct {
	// From — ключ родителя (менеджер:имя:версия). Пусто у заявленного пакета.
	From string
	// Constraint — требование родителя, как оно записано в реестре.
	Constraint string
	// Note — пояснение от плагина (indirect, target framework, маркер).
	Note string
}

// Problem — зависимость, которую не удалось раскрыть. Это не ошибка сервиса:
// раскрытие идёт по данным реестра, и в них встречается всякое. Каждый такой
// случай обязан быть назван — «недоступный резолвер не значит, что
// зависимостей нет».
type Problem struct {
	Name       string
	Constraint string
	ParentKey  string
	Depth      int
	Reason     string
}

// Conflict — один пакет затребован в разных версиях.
type Conflict struct {
	Name     string
	Versions []string
}

// Result — итог раскрытия.
type Result struct {
	// Nodes — все узлы, включая заявленные (Depth == 0), в порядке обхода.
	Nodes     []Node
	Problems  []Problem
	Conflicts []Conflict
	// Truncated — обход упёрся в лимит: показанное дерево неполное, и об этом
	// нельзя молчать.
	Truncated bool
	MaxDepth  int
	Requests  int
	CacheHits int
	// Options — с какими пределами шёл обход. Нужны, чтобы объяснить
	// обрезанное дерево: «предел 200» — ответ, «дерево неполное» — нет.
	Options Options
}

// Transitive — узлы глубже нуля.
func (r Result) Transitive() []Node {
	var out []Node
	for _, node := range r.Nodes {
		if node.Depth > 0 {
			out = append(out, node)
		}
	}
	return out
}

// Options — пределы обхода.
type Options struct {
	// MaxDepth — до какой глубины раскрывать. 1 — только прямые зависимости.
	MaxDepth int
	// MaxNodes — предел размера дерева. Один популярный пакет притаскивает
	// сотни: без предела заявка превратится в неподъёмную для людей очередь,
	// а сервис — в источник тысяч запросов к реестру.
	MaxNodes int
	// IncludeOptional — раскрывать необязательные зависимости (extras у pypi,
	// optionalDependencies у npm). По умолчанию нет: их нет в обычной
	// установке.
	IncludeOptional bool
	// Concurrency — сколько узлов раскрывается одновременно.
	Concurrency int
}

// DefaultOptions — значения по умолчанию.
func DefaultOptions() Options {
	return Options{MaxDepth: 3, MaxNodes: 200, Concurrency: 8}
}

func (o Options) normalized() Options {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 1
	}
	if o.MaxNodes <= 0 {
		o.MaxNodes = DefaultOptions().MaxNodes
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 1
	}
	return o
}

// ErrUnsupported — менеджер не умеет раскрывать зависимости.
var ErrUnsupported = errors.New("менеджер не умеет раскрывать зависимости")

// Resolver — раскрытие по реестрам.
type Resolver struct {
	Registry *registry.Registry
	Options  Options
	Logger   *slog.Logger
}

// New собирает резолвер.
func New(reg *registry.Registry, opts Options, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Resolver{Registry: reg, Options: opts.normalized(), Logger: logger}
}

// Supports — менеджер умеет раскрывать зависимости.
func (r *Resolver) Supports(manager string) bool {
	plugin, err := r.Registry.Get(manager)
	if err != nil {
		return false
	}
	_, ok := plugin.(registry.DependencyResolver)
	return ok
}

// Key — ключ узла: менеджер, имя и версия.
func Key(ref registry.Ref) string {
	return ref.Manager + ":" + ref.Name + ":" + ref.Version
}

// Walk раскрывает дерево от заявленных пакетов вширь: сначала все прямые
// зависимости, потом их зависимости. Обход именно вширь, а не вглубь, чтобы
// упор в MaxNodes обрезал самые дальние узлы, а не случайную ветку целиком.
func (r *Resolver) Walk(ctx context.Context, manager string, roots []registry.Ref) (Result, error) {
	return r.WalkWith(ctx, manager, roots, r.Options)
}

// WalkWith — то же с пределами на один вызов: у предпросмотра и у создания
// заявки они разные (предел заявки главнее настроек обхода).
func (r *Resolver) WalkWith(ctx context.Context, manager string, roots []registry.Ref, opts Options) (Result, error) {
	opts = opts.normalized()
	plugin, err := r.Registry.Get(manager)
	if err != nil {
		return Result{}, err
	}
	source, ok := plugin.(registry.DependencyResolver)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrUnsupported, manager)
	}
	scheme, err := version.For(manager)
	if err != nil {
		return Result{}, err
	}

	state := &walkState{
		resolver: r, options: opts, plugin: plugin, source: source, scheme: scheme,
		index: map[string]int{}, versionsByName: map[string][]string{},
	}
	for _, ref := range roots {
		state.add(Node{Ref: ref, Depth: 0, Parents: []Edge{{}}})
	}

	frontier := append([]Node(nil), state.result.Nodes...)
	for depth := 1; depth <= opts.MaxDepth && len(frontier) > 0; depth++ {
		if state.result.Truncated {
			break
		}
		frontier = state.expandLevel(ctx, frontier, depth)
	}

	state.finish()
	state.result.Options = opts
	return state.result, nil
}

type walkState struct {
	resolver *Resolver
	options  Options
	plugin   registry.Plugin
	source   registry.DependencyResolver
	scheme   version.Scheme

	mu             sync.Mutex
	result         Result
	index          map[string]int // ключ узла -> позиция в result.Nodes
	versionsByName map[string][]string
}

// add добавляет узел или дописывает родителя уже известному. Возвращает
// true, если узел новый и его нужно раскрывать дальше.
func (s *walkState) add(node Node) bool {
	key := Key(node.Ref)
	if idx, ok := s.index[key]; ok {
		s.result.Nodes[idx].Parents = append(s.result.Nodes[idx].Parents, node.Parents...)
		return false
	}
	if len(s.result.Nodes) >= s.options.MaxNodes {
		s.result.Truncated = true
		return false
	}
	s.index[key] = len(s.result.Nodes)
	s.result.Nodes = append(s.result.Nodes, node)
	if node.Depth > s.result.MaxDepth {
		s.result.MaxDepth = node.Depth
	}
	return true
}

// expandLevel раскрывает один уровень дерева и возвращает следующий.
func (s *walkState) expandLevel(ctx context.Context, level []Node, depth int) []Node {
	limit := make(chan struct{}, s.options.Concurrency)
	var wg sync.WaitGroup
	var next []Node
	var nextMu sync.Mutex

	for _, parent := range level {
		wg.Add(1)
		go func(parent Node) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()

			children := s.children(ctx, parent, depth)
			nextMu.Lock()
			next = append(next, children...)
			nextMu.Unlock()
		}(parent)
	}
	wg.Wait()

	// Порядок узлов в результате не должен зависеть от того, какая горутина
	// успела первой: заявка с одним и тем же входом обязана выглядеть
	// одинаково, иначе её невозможно сверить между прогонами.
	sort.SliceStable(next, func(i, j int) bool { return Key(next[i].Ref) < Key(next[j].Ref) })

	var accepted []Node
	s.mu.Lock()
	for _, child := range next {
		if s.add(child) {
			accepted = append(accepted, child)
		}
	}
	s.mu.Unlock()
	return accepted
}

// children раскрывает зависимости одного узла.
func (s *walkState) children(ctx context.Context, parent Node, depth int) []Node {
	parentKey := Key(parent.Ref)
	requirements, err := s.source.Requirements(ctx, parent.Ref)
	s.countRequest()
	if err != nil {
		s.problem(Problem{Name: parent.Ref.DisplayName, Depth: depth - 1, ParentKey: parentKey,
			Reason: "не удалось прочитать зависимости: " + err.Error()})
		return nil
	}

	var out []Node
	for _, req := range requirements {
		if req.Optional && !s.options.IncludeOptional {
			continue
		}
		child, problem := s.resolveRequirement(ctx, req, parentKey, depth)
		if problem != nil {
			s.problem(*problem)
			continue
		}
		out = append(out, *child)
	}
	return out
}

func (s *walkState) resolveRequirement(ctx context.Context, req registry.Requirement, parentKey string, depth int) (*Node, *Problem) {
	problem := &Problem{Name: req.Name, Constraint: req.Constraint, ParentKey: parentKey, Depth: depth}

	if err := s.plugin.ValidateName(req.Name); err != nil {
		problem.Reason = "имя не проходит проверку менеджера: " + err.Error()
		return nil, problem
	}
	available, err := s.versions(ctx, req.Name)
	if err != nil {
		problem.Reason = "реестр не отдал версии: " + err.Error()
		return nil, problem
	}
	picked, err := s.scheme.Select(req.Constraint, available)
	if err != nil {
		switch {
		case errors.Is(err, version.ErrNoMatch):
			problem.Reason = fmt.Sprintf("в реестре нет версии под требование «%s» (версий: %d)",
				req.Constraint, len(available))
		case errors.Is(err, version.ErrBadConstraint):
			problem.Reason = "требование не разобрано: " + err.Error()
		default:
			problem.Reason = err.Error()
		}
		return nil, problem
	}
	ref, err := registry.MakeRef(s.plugin, req.Name, picked)
	if err != nil {
		problem.Reason = err.Error()
		return nil, problem
	}
	return &Node{Ref: ref, Depth: depth,
		Parents: []Edge{{From: parentKey, Constraint: req.Constraint, Note: req.Note}}}, nil
}

// versions — список версий пакета с кэшем на время одного раскрытия. Без
// кэша дерево из сотни узлов дало бы сотни повторных запросов к реестру: один
// и тот же пакет требуется многими.
func (s *walkState) versions(ctx context.Context, name string) ([]string, error) {
	key := s.plugin.NormalizeName(name)
	s.mu.Lock()
	cached, ok := s.versionsByName[key]
	s.mu.Unlock()
	if ok {
		s.mu.Lock()
		s.result.CacheHits++
		s.mu.Unlock()
		return cached, nil
	}

	available, err := s.source.Versions(ctx, name)
	s.countRequest()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.versionsByName[key] = available
	s.mu.Unlock()
	return available, nil
}

func (s *walkState) countRequest() {
	s.mu.Lock()
	s.result.Requests++
	s.mu.Unlock()
}

func (s *walkState) problem(p Problem) {
	s.mu.Lock()
	s.result.Problems = append(s.result.Problems, p)
	s.mu.Unlock()
}

// finish приводит результат к стабильному виду и собирает конфликты версий.
func (s *walkState) finish() {
	byName := map[string][]string{}
	for _, node := range s.result.Nodes {
		byName[node.Ref.Name] = append(byName[node.Ref.Name], node.Ref.Version)
	}
	for name, versions := range byName {
		if len(versions) < 2 {
			continue
		}
		sort.Strings(versions)
		s.result.Conflicts = append(s.result.Conflicts, Conflict{Name: name, Versions: versions})
	}
	sort.Slice(s.result.Conflicts, func(i, j int) bool {
		return s.result.Conflicts[i].Name < s.result.Conflicts[j].Name
	})
	sort.SliceStable(s.result.Problems, func(i, j int) bool {
		if s.result.Problems[i].Depth != s.result.Problems[j].Depth {
			return s.result.Problems[i].Depth < s.result.Problems[j].Depth
		}
		return s.result.Problems[i].Name < s.result.Problems[j].Name
	})
}

// Summary — короткое описание итога для предупреждений в заявке.
func (r Result) Summary() string {
	transitive := len(r.Transitive())
	parts := []string{fmt.Sprintf("транзитивных зависимостей: %d", transitive)}
	if r.MaxDepth > 0 {
		parts = append(parts, fmt.Sprintf("глубина: %d", r.MaxDepth))
	}
	if len(r.Problems) > 0 {
		parts = append(parts, fmt.Sprintf("не раскрыто: %d", len(r.Problems)))
	}
	if len(r.Conflicts) > 0 {
		parts = append(parts, fmt.Sprintf("конфликтов версий: %d", len(r.Conflicts)))
	}
	if r.Truncated {
		parts = append(parts, "дерево обрезано по пределу")
	}
	return strings.Join(parts, "; ")
}
