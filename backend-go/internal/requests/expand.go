package requests

import (
	"context"
	"fmt"
	"sort"

	"moderation/internal/registry"
	"moderation/internal/resolve"
)

// transitiveResolvedWarning — что увидит автор заявки, когда раскрытие
// отработало. Текст «зависимости не подтягиваются» больше не годится: теперь
// подтягиваются, и человек должен понимать, за что он отвечает.
const transitiveResolvedWarning = "Транзитивные зависимости раскрыты по данным реестра: " +
	"каждая из них проходит модерацию как отдельный пакет заявки."

// Expand дополняет разбор транзитивными зависимостями. Возвращает дополненный
// результат и итог обхода — по нему видно, полное ли дерево.
//
// Почему отдельным шагом, а не внутри Parse: раскрытие ходит в реестр по
// каждому узлу, и это единственная часть создания заявки, которая может
// занять секунды. Держать её отдельно значит иметь возможность показать
// дерево пользователю ДО создания заявки (предпросмотр) и создавать заявку
// без похода наружу, когда раскрытие не просили.
func (s *Service) Expand(ctx context.Context, result ParseResult, opts resolve.Options) (ParseResult, *resolve.Result, error) {
	if s.Resolver == nil {
		return result, nil, nil
	}
	if !s.Resolver.Supports(result.Manager) {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"Менеджер «%s» пока не умеет раскрывать зависимости: заведены только перечисленные пакеты.",
			result.Manager))
		return result, nil, nil
	}

	// Корни — всё, что разобралось: и новое, и уже лежащее в базе. Пакет,
	// одобренный раньше, всё равно тянет за собой зависимости, и их могли не
	// смотреть — раскрытие появилось позже.
	var roots []registry.Ref
	known := map[string]bool{}
	for _, pkg := range result.Packages {
		if pkg.Ref == nil {
			continue
		}
		roots = append(roots, *pkg.Ref)
		known[resolve.Key(*pkg.Ref)] = true
	}
	if len(roots) == 0 {
		return result, nil, nil
	}

	// Предел заявки главнее предела обхода: иначе раскрытие завело бы больше
	// пакетов, чем разрешено заводить руками.
	maxPackages := s.Limits.MaxPackages
	if maxPackages <= 0 {
		maxPackages = 200
	}
	if opts.MaxNodes <= 0 || opts.MaxNodes > maxPackages {
		opts.MaxNodes = maxPackages
	}

	walk, err := s.Resolver.WalkWith(ctx, result.Manager, roots, opts)
	if err != nil {
		return result, nil, err
	}

	// Узлы идут по возрастанию глубины: родитель обязан попасть в заявку
	// раньше потомка, иначе связать их будет нечем.
	nodes := walk.Transitive()
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		return resolve.Key(nodes[i].Ref) < resolve.Key(nodes[j].Ref)
	})

	added := 0
	for _, node := range nodes {
		key := resolve.Key(node.Ref)
		if known[key] {
			continue
		}
		known[key] = true

		parsed, err := s.classify(ctx, node.Ref, node.Ref.Entry(), "transitive")
		if err != nil {
			return result, nil, err
		}
		parsed.Depth = node.Depth
		// Родитель — первый в списке: обход идёт вширь, поэтому первым
		// записан тот, через кого пакет попал в дерево кратчайшим путём.
		// Остальные пути в карточке не показываются: в дереве из сотни узлов
		// они превращают полезную строку «пришло через X» в простыню.
		if len(node.Parents) > 0 {
			parsed.ParentKey = node.Parents[0].From
			parsed.RequiredRange = node.Parents[0].Constraint
		}
		result.Packages = append(result.Packages, parsed)
		added++
	}

	if added > 0 {
		result.Warnings = append(result.Warnings, transitiveResolvedWarning)
	}
	result.Warnings = append(result.Warnings, walkWarnings(walk)...)
	return result, &walk, nil
}

// walkWarnings переводит итог обхода в предупреждения заявки. Каждое из них —
// про то, чего в заявке НЕТ: неполное дерево выглядит точно так же, как
// полное, и единственное, что их различает, — эти строки.
func walkWarnings(walk resolve.Result) []string {
	var out []string
	if walk.Truncated {
		out = append(out, fmt.Sprintf(
			"Дерево зависимостей обрезано по пределу заявки: показана часть. "+
				"Заведите оставшееся отдельной заявкой или поднимите предел (узлов: %d).",
			len(walk.Nodes)))
	}
	if len(walk.Problems) > 0 {
		names := make([]string, 0, len(walk.Problems))
		for _, problem := range walk.Problems {
			names = append(names, fmt.Sprintf("%s (%s)", problem.Name, problem.Reason))
		}
		out = append(out, "Не удалось раскрыть зависимости: "+joinLimited(names, 5)+
			". Эти пакеты в заявку не попали — проверьте их вручную.")
	}
	for _, conflict := range walk.Conflicts {
		out = append(out, fmt.Sprintf(
			"Пакет «%s» затребован в разных версиях: %s. В заявку заведены обе — "+
				"выбор версии за вами.", conflict.Name, joinLimited(conflict.Versions, 5)))
	}
	return out
}

func joinLimited(items []string, limit int) string {
	if len(items) <= limit {
		return joinComma(items)
	}
	return fmt.Sprintf("%s и ещё %d", joinComma(items[:limit]), len(items)-limit)
}

func joinComma(items []string) string {
	out := ""
	for i, item := range items {
		if i > 0 {
			out += ", "
		}
		out += item
	}
	return out
}
