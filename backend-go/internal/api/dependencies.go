package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"moderation/internal/requests"
	"moderation/internal/resolve"
)

// Предпросмотр дерева зависимостей: что заявка потянет за собой, ДО её
// создания.
//
// Зачем отдельный маршрут, а если заявку всё равно можно создать с
// include_transitive. Человек, который добавляет пакет, не знает, во что
// обойдётся его решение: «requests» — это четыре пакета, «webpack» — сотня.
// Увидеть дерево до отправки значит не заводить заявку на сто пакетов
// случайно, а увидев — сузить глубину или отказаться.

// MountDependencies подключает маршрут предпросмотра.
func MountDependencies(r chi.Router, h *RequestsHandler, a *Auth) {
	if h.Requests == nil {
		// Разбора заявок нет — предпросматривать нечего. Честно не иметь
		// маршрута лучше, чем отдавать 500 на кнопку.
		return
	}
	r.Route("/api/v1/dependencies", func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Post("/resolve", h.ResolveDependencies)
	})
}

// ResolveDependencies — POST /api/v1/dependencies/resolve.
func (h *RequestsHandler) ResolveDependencies(w http.ResponseWriter, r *http.Request) {
	if _, ok := CurrentUser(r.Context()); !ok {
		writeError(w, r, errInternal("Маршрут предпросмотра не закрыт проверкой токена"))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, r, errValidation("Тело запроса не прочитано").Because(err))
		return
	}
	var payload struct {
		Manager         string   `json:"manager"`
		Packages        []string `json:"packages"`
		Depth           int      `json:"depth"`
		IncludeOptional bool     `json:"include_optional"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, r, errValidation("Тело запроса не является корректным JSON").Because(err))
		return
	}
	manager := strings.ToLower(strings.TrimSpace(payload.Manager))
	if manager == "" {
		writeError(w, r, errValidation("Не указан пакетный менеджер (поле manager)"))
		return
	}
	var entries []string
	for _, entry := range payload.Packages {
		if strings.TrimSpace(entry) != "" {
			entries = append(entries, strings.TrimSpace(entry))
		}
	}
	if len(entries) == 0 {
		writeError(w, r, errValidation("Список packages пуст"))
		return
	}

	parsed, err := h.Requests.Parse(r.Context(), requests.Input{Manager: manager, Entries: entries})
	if err != nil {
		writeError(w, r, createError(err))
		return
	}

	opts := h.resolveOptions(payload.Depth)
	opts.IncludeOptional = opts.IncludeOptional || payload.IncludeOptional
	expanded, walk, err := h.Requests.Expand(r.Context(), parsed, opts)
	if err != nil {
		writeError(w, r, errBadGateway(
			"Не удалось раскрыть зависимости: реестр не ответил").Because(err))
		return
	}

	writeJSON(w, http.StatusOK, dependencyTreeView(manager, expanded, walk, opts))
}

func dependencyTreeView(manager string, parsed requests.ParseResult, walk *resolve.Result, opts resolve.Options) map[string]any {
	packages := make([]map[string]any, 0, len(parsed.Packages))
	transitive := 0
	for _, pkg := range parsed.Packages {
		view := parsedPackageView(pkg)
		view["depth"] = pkg.Depth
		if pkg.Depth > 0 {
			transitive++
			view["required_by"] = parentEntry(pkg.ParentKey)
			view["required_range"] = pkg.RequiredRange
		}
		packages = append(packages, view)
	}

	out := map[string]any{
		"manager":    manager,
		"packages":   packages,
		"direct":     len(packages) - transitive,
		"transitive": transitive,
		"warnings":   listOrEmpty(parsed.Warnings),
		"limits": map[string]any{
			"max_depth":    opts.MaxDepth,
			"max_packages": opts.MaxNodes,
		},
	}
	if walk == nil {
		// Раскрытия не было: менеджер его не поддерживает. Молчаливый пустой
		// список выглядел бы как «зависимостей нет».
		out["resolved"] = false
		return out
	}

	problems := make([]map[string]any, 0, len(walk.Problems))
	for _, problem := range walk.Problems {
		problems = append(problems, map[string]any{
			"name":        problem.Name,
			"constraint":  problem.Constraint,
			"required_by": parentEntry(problem.ParentKey),
			"depth":       problem.Depth,
			"reason":      problem.Reason,
		})
	}
	conflicts := make([]map[string]any, 0, len(walk.Conflicts))
	for _, conflict := range walk.Conflicts {
		conflicts = append(conflicts, map[string]any{
			"name": conflict.Name, "versions": conflict.Versions,
		})
	}

	out["resolved"] = true
	out["depth"] = walk.MaxDepth
	out["truncated"] = walk.Truncated
	out["problems"] = problems
	out["conflicts"] = conflicts
	out["summary"] = walk.Summary()
	out["registry_requests"] = walk.Requests
	return out
}

// itemTreeView — поля дерева для пакета заявки. Отдельной функцией, потому
// что карточка заявки и очередь роли показывают их одинаково.
func itemTreeView(view map[string]any, parentID *int64, depth int, required *string) map[string]any {
	view["depth"] = depth
	if parentID != nil {
		view["parent_item_id"] = *parentID
		view["parent_link"] = "/api/v1/request-items/" + strconv.FormatInt(*parentID, 10)
	}
	if required != nil && *required != "" {
		view["required_range"] = *required
	}
	return view
}
